"""Ingest runner: parallel chunked Parquet ingest for large security logs."""

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import time
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from app.pipeline.ingest.parsers import fortigate_kv
from app.store import duck


def get_peak_rss_mb() -> float:
    """Return peak resident set size in megabytes for the current process."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            proc_query = 0x0400 | 0x0010
            handle = ctypes.windll.kernel32.OpenProcess(proc_query, False, os.getpid())
            if handle:
                try:
                    if ctypes.windll.psapi.GetProcessMemoryInfo(
                        handle, ctypes.byref(counters), counters.cb
                    ):
                        return round(counters.PeakWorkingSetSize / (1024 * 1024), 2)
                finally:
                    ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass
        return 0.0
    else:
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform == "darwin":
                return round(usage / (1024 * 1024), 2)
            return round(usage / 1024, 2)
        except Exception:
            return 0.0


def compute_chunk_ranges(
    path: str,
    chunk_size: int = 64 * 1024 * 1024,
    limit_bytes: int | None = None,
) -> list[tuple[int, int]]:
    """Compute newline-aligned byte ranges for parallel processing.
    
    Every range [start, end) starts and ends exactly on line boundaries.
    """
    total_size = os.path.getsize(path)
    max_bytes = min(limit_bytes, total_size) if limit_bytes is not None else total_size

    ranges: list[tuple[int, int]] = []
    start = 0

    with open(path, "rb") as f:
        while start < max_bytes:
            nominal_end = min(start + chunk_size, max_bytes)
            if nominal_end >= total_size or nominal_end >= max_bytes:
                if nominal_end < total_size:
                    f.seek(nominal_end)
                    buf = f.read(65536)
                    nl = buf.find(b"\n")
                    if nl != -1:
                        nominal_end += nl + 1
                    else:
                        nominal_end = total_size
                else:
                    nominal_end = total_size
                ranges.append((start, nominal_end))
                break

            f.seek(nominal_end)
            buf = f.read(65536)
            nl = buf.find(b"\n")
            if nl != -1:
                aligned_end = nominal_end + nl + 1
            else:
                aligned_end = nominal_end

            ranges.append((start, aligned_end))
            start = aligned_end

    return ranges


def _process_chunk_worker(
    chunk_index: int,
    file_path: str,
    start_byte: int,
    end_byte: int,
    stream_id: int = 0,
    out_base_dir: str = "data/parquet",
    skip_bad: bool = False,
) -> dict[str, Any]:
    """Worker function: parses a byte range and writes Parquet."""
    file_name = os.path.basename(file_path)
    total_bytes = end_byte - start_byte

    lines = 0
    parsed = 0
    malformed = 0
    records: list[dict[str, Any]] = []
    ts_min: str | None = None
    ts_max: str | None = None

    printable_bytes = 0
    sampled_bytes = 0

    with open(file_path, "rb") as fh:
        fh.seek(start_byte)
        # Sample first 64KB for printable ratio
        sample_buf = fh.read(min(65536, total_bytes))
        sampled_bytes = len(sample_buf)
        if sampled_bytes > 0:
            for b in sample_buf:
                if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D):
                    printable_bytes += 1
            printable_ratio = printable_bytes / sampled_bytes
        else:
            printable_ratio = 1.0

        fh.seek(start_byte)
        while fh.tell() < end_byte:
            offset = fh.tell()
            raw_b = fh.readline()
            if not raw_b:
                break
            lines += 1
            raw_s = raw_b.decode("utf-8", errors="replace")
            rec = fortigate_kv.parse_line(raw_s, file_name, offset, stream=stream_id)
            if rec is None:
                malformed += 1
            else:
                parsed += 1
                ts = rec["timestamp"]
                if ts_min is None or ts < ts_min:
                    ts_min = ts
                if ts_max is None or ts > ts_max:
                    ts_max = ts
                records.append(rec)

    valid_share = (parsed / lines) if lines > 0 else 0.0
    if printable_ratio >= 0.90 and valid_share >= 0.80:
        classification = "text"
    elif valid_share >= 0.10 or printable_ratio >= 0.70:
        classification = "mixed"
    else:
        classification = "binary"

    skipped = False
    parquet_path: str | None = None

    if classification == "binary" and skip_bad:
        skipped = True
    elif records:
        chunk_dir = os.path.join(out_base_dir, f"stream={stream_id}", f"chunk={chunk_index}")
        os.makedirs(chunk_dir, exist_ok=True)
        parquet_path = os.path.join(chunk_dir, "part-0.parquet")
        table = pa.Table.from_pylist(records)
        pq.write_table(
            table,
            parquet_path,
            compression="zstd",
            row_group_size=500_000,
            use_dictionary=True,
        )

    return {
        "chunk_index": chunk_index,
        "start_byte": start_byte,
        "end_byte": end_byte,
        "bytes": total_bytes,
        "lines": lines,
        "parsed": parsed,
        "malformed": malformed,
        "ts_min": ts_min,
        "ts_max": ts_max,
        "printable_ratio": round(printable_ratio, 4),
        "valid_share": round(valid_share, 4),
        "classification": classification,
        "skipped": skipped,
        "parquet_file": parquet_path,
    }


def run_ingest(
    job_id: str,
    paths: list[str],
    chunk_size: int = 64 * 1024 * 1024,
    workers: int | None = None,
    resume: bool = False,
    skip_bad: bool = False,
    limit_bytes: int | None = None,
    stream_id: int = 0,
    out_base_dir: str = "data/parquet",
) -> dict[str, Any]:
    """Ingest log files using parallel chunked Parquet writing."""
    if not paths:
        return {"files_ingested": 0, "total_events": 0, "malformed_lines": 0}

    main_path = paths[0]
    if not os.path.exists(main_path):
        raise FileNotFoundError(f"Log file not found: {main_path}")

    num_workers = workers if workers and workers > 0 else max(1, (os.cpu_count() or 2) - 1)
    manifest_path = os.path.join(out_base_dir, "_manifest.json")

    completed_chunks: dict[int, dict[str, Any]] = {}
    if resume and os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as f:
                old_mf = json.load(f)
                for ch in old_mf.get("chunks", []):
                    idx = ch.get("chunk_index")
                    pq_f = ch.get("parquet_file")
                    if idx is not None and (ch.get("skipped") or (pq_f and os.path.exists(pq_f))):
                        completed_chunks[idx] = ch
        except Exception:
            pass

    ranges = compute_chunk_ranges(main_path, chunk_size=chunk_size, limit_bytes=limit_bytes)
    total_chunks = len(ranges)

    t0 = time.perf_counter()
    chunk_results: list[dict[str, Any]] = []
    tasks_to_run: list[tuple[int, int, int]] = []

    for idx, (s_byte, e_byte) in enumerate(ranges):
        if idx in completed_chunks:
            chunk_results.append(completed_chunks[idx])
        else:
            tasks_to_run.append((idx, s_byte, e_byte))

    last_update_time = time.time()
    total_processed_bytes = sum(ch.get("bytes", 0) for ch in chunk_results)

    if tasks_to_run:
        with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = {
                executor.submit(
                    _process_chunk_worker,
                    idx,
                    main_path,
                    s_byte,
                    e_byte,
                    stream_id,
                    out_base_dir,
                    skip_bad,
                ): idx
                for (idx, s_byte, e_byte) in tasks_to_run
            }

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                chunk_results.append(res)
                total_processed_bytes += res["bytes"]

                # Report progress every second
                now = time.time()
                if now - last_update_time >= 1.0 or len(chunk_results) == total_chunks:
                    last_update_time = now
                    pct = round((len(chunk_results) / total_chunks) * 100, 1)
                    duck.update_job(job_id, progress_pct=pct)

    t1 = time.perf_counter()
    elapsed = max(0.001, t1 - t0)

    # Sort chunk results by index
    chunk_results.sort(key=lambda x: x["chunk_index"])

    total_lines = sum(ch.get("lines", 0) for ch in chunk_results)
    total_events = sum(ch.get("parsed", 0) for ch in chunk_results)
    total_malformed = sum(ch.get("malformed", 0) for ch in chunk_results)
    bad_chunks = [ch for ch in chunk_results if ch.get("classification") == "binary"]
    skipped_chunks = [ch for ch in chunk_results if ch.get("skipped")]

    # Calculate parquet size
    total_parquet_size = 0
    for ch in chunk_results:
        pq_path = ch.get("parquet_file")
        if pq_path and os.path.exists(pq_path):
            total_parquet_size += os.path.getsize(pq_path)

    peak_rss = get_peak_rss_mb()

    # Save manifest
    manifest_data = {
        "source_file": os.path.abspath(main_path),
        "total_file_bytes": os.path.getsize(main_path),
        "bytes_ingested": total_processed_bytes,
        "total_lines": total_lines,
        "total_events": total_events,
        "malformed_lines": total_malformed,
        "total_chunks": total_chunks,
        "bad_chunks_count": len(bad_chunks),
        "skipped_chunks_count": len(skipped_chunks),
        "elapsed_seconds": round(elapsed, 2),
        "peak_rss_mb": peak_rss,
        "parquet_size_bytes": total_parquet_size,
        "chunks": chunk_results,
    }

    os.makedirs(out_base_dir, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    # Refresh DuckDB view over the parquet files
    duck.ensure_events_view(out_base_dir)

    # Update stats in DuckDB
    duck.set_stat("last_ingest_events", str(total_events))
    duck.set_stat("last_ingest_malformed", str(total_malformed))
    duck.set_stat("last_ingest_bytes", str(total_processed_bytes))
    duck.set_stat("last_ingest_bad_chunks", str(len(bad_chunks)))
    duck.set_stat("last_ingest_time_seconds", str(round(elapsed, 2)))
    duck.set_stat("last_ingest_parquet_size", str(total_parquet_size))

    return {
        "source_file": main_path,
        "files_ingested": len(paths),
        "total_bytes": total_processed_bytes,
        "total_lines": total_lines,
        "total_events": total_events,
        "malformed_lines": total_malformed,
        "total_chunks": total_chunks,
        "bad_chunks": len(bad_chunks),
        "skipped_chunks": len(skipped_chunks),
        "elapsed_seconds": round(elapsed, 2),
        "lines_per_sec": round(total_lines / elapsed, 0),
        "mb_per_sec": round((total_processed_bytes / (1024 * 1024)) / elapsed, 2),
        "peak_memory_mb": peak_rss,
        "parquet_size_bytes": total_parquet_size,
        "bad_chunks_info": [
            {
                "chunk_index": ch["chunk_index"],
                "start_byte": ch["start_byte"],
                "end_byte": ch["end_byte"],
                "classification": ch["classification"],
                "skipped": ch.get("skipped", False),
            }
            for ch in bad_chunks
        ],
    }
