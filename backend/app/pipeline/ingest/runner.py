"""Ingest runner: parallel chunked Parquet ingest for large security logs."""

from __future__ import annotations

import concurrent.futures
import json
import os
import time
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from app.config import settings
from app.pipeline.ingest.parsers import fortigate_kv
from app.store import duck

ALL_FIELDS = [
    ("event_id", pa.string()),
    ("timestamp", pa.string()),
    ("eventtime_ns", pa.int64()),
    ("host", pa.string()),
    ("sensor", pa.string()),
    ("user", pa.string()),
    ("user_raw", pa.string()),
    ("src_ip", pa.string()),
    ("dst_ip", pa.string()),
    ("src_port", pa.int64()),
    ("dst_port", pa.int64()),
    ("event_type", pa.string()),
    ("action", pa.string()),
    ("outcome", pa.string()),
    ("bytes_out", pa.int64()),
    ("bytes_in", pa.int64()),
    ("url", pa.string()),
    ("hostname", pa.string()),
    ("attack", pa.string()),
    ("attackid", pa.string()),
    ("severity", pa.string()),
    ("log_format", pa.string()),
    ("stream", pa.int64()),
    ("source_file", pa.string()),
    ("source_offset", pa.int64()),
    ("app", pa.string()),
    ("appcat", pa.string()),
    ("apprisk", pa.string()),
    ("catdesc", pa.string()),
    ("devid", pa.string()),
    ("devname", pa.string()),
    ("dstcountry", pa.string()),
    ("dstintf", pa.string()),
    ("dstintfrole", pa.string()),
    ("dstip", pa.string()),
    ("dstport", pa.int64()),
    ("duration", pa.int64()),
    ("level", pa.string()),
    ("logdesc", pa.string()),
    ("logid", pa.string()),
    ("method", pa.string()),
    ("msg", pa.string()),
    ("policyid", pa.string()),
    ("proto", pa.int64()),
    ("rcvdbyte", pa.int64()),
    ("rcvdpkt", pa.int64()),
    ("reason", pa.string()),
    ("sentbyte", pa.int64()),
    ("sentpkt", pa.int64()),
    ("service", pa.string()),
    ("sessionid", pa.int64()),
    ("srccountry", pa.string()),
    ("srcintf", pa.string()),
    ("srcintfrole", pa.string()),
    ("srcip", pa.string()),
    ("srcport", pa.int64()),
    ("status", pa.string()),
    ("subtype", pa.string()),
    ("type", pa.string()),
    ("ui", pa.string()),
    ("vd", pa.string()),
    ("virus", pa.string()),
    ("extra", pa.string()),
]

PARQUET_SCHEMA = pa.schema(ALL_FIELDS)
FIELD_NAMES = [f[0] for f in ALL_FIELDS]


def get_peak_rss_mb() -> float:
    """Return peak resident set size in megabytes for the whole process tree."""
    try:
        import psutil
        root = psutil.Process()
        total_rss = root.memory_info().rss
        for child in root.children(recursive=True):
            try:
                total_rss += child.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return round(total_rss / (1024 * 1024), 2)
    except Exception:
        return 0.0


def compute_chunk_ranges(
    path: str,
    chunk_size: int = 64 * 1024 * 1024,
    limit_bytes: int | None = None,
    start_offset: int = 0,
) -> list[tuple[int, int]]:
    """Compute newline-aligned byte ranges for parallel processing.
    
    Every range [start, end) starts and ends exactly on line boundaries.
    """
    total_size = os.path.getsize(path)
    start = max(0, start_offset)
    if start >= total_size:
        return []

    ranges: list[tuple[int, int]] = []

    with open(path, "rb") as f:
        if start > 0:
            f.seek(start)
            buf = f.read(65536)
            nl = buf.find(b"\n")
            if nl != -1:
                start = start + nl + 1
            else:
                return []

        max_bytes = min(start + limit_bytes, total_size) if limit_bytes is not None else total_size
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
    parse_only: bool = False,
    batch_rows: int = 50_000,
    compression: str = "zstd",
) -> dict[str, Any]:
    """Worker function: parses a byte range and streams row groups via ParquetWriter."""
    file_name = os.path.basename(file_path)
    total_bytes = end_byte - start_byte

    lines = 0
    parsed = 0
    malformed = 0
    ts_min: str | None = None
    ts_max: str | None = None

    printable_bytes = 0
    sampled_bytes = 0

    batch_cols: dict[str, list[Any]] = {name: [] for name in FIELD_NAMES}
    parquet_path: str | None = None
    writer: pq.ParquetWriter | None = None

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
        block_size = 8 * 1024 * 1024
        curr_offset = start_byte
        remainder = b""

        def _flush_batch() -> None:
            nonlocal writer, parquet_path
            if parse_only or not batch_cols["event_id"]:
                return
            if parquet_path is None:
                chunk_dir = os.path.join(out_base_dir, f"stream={stream_id}", f"chunk={chunk_index}")
                os.makedirs(chunk_dir, exist_ok=True)
                parquet_path = os.path.join(chunk_dir, "part-0.parquet")
                writer = pq.ParquetWriter(
                    parquet_path,
                    PARQUET_SCHEMA,
                    compression=compression,
                    use_dictionary=True,
                )
            tbl = pa.Table.from_pydict(batch_cols, schema=PARQUET_SCHEMA)
            writer.write_table(tbl)
            for col in batch_cols.values():
                col.clear()

        def _handle_line(line_b: bytes, line_off: int) -> None:
            nonlocal lines, parsed, malformed, ts_min, ts_max
            lines += 1
            raw_s = line_b.decode("utf-8", errors="replace")
            rec = fortigate_kv.parse_line(raw_s, file_name, line_off, stream=stream_id)
            if rec is None:
                malformed += 1
                return
            parsed += 1
            ts = rec["timestamp"]
            if ts_min is None or ts < ts_min:
                ts_min = ts
            if ts_max is None or ts > ts_max:
                ts_max = ts

            if not parse_only:
                for k in FIELD_NAMES:
                    batch_cols[k].append(rec.get(k))
                if len(batch_cols["event_id"]) >= batch_rows:
                    _flush_batch()

        while curr_offset < end_byte or remainder:
            to_read = min(block_size, end_byte - curr_offset)
            buf = fh.read(to_read) if to_read > 0 else b""
            if not buf and not remainder:
                break
            data = remainder + buf
            data_base_offset = curr_offset - len(remainder)
            curr_offset += len(buf)

            start_idx = 0
            while True:
                nl = data.find(b"\n", start_idx)
                if nl == -1:
                    remainder = data[start_idx:]
                    if curr_offset >= end_byte and remainder:
                        _handle_line(remainder, data_base_offset + start_idx)
                        remainder = b""
                    break

                line_b = data[start_idx : nl + 1]
                line_off = data_base_offset + start_idx
                start_idx = nl + 1
                _handle_line(line_b, line_off)

    valid_share = (parsed / lines) if lines > 0 else 0.0
    if printable_ratio >= 0.90 and valid_share >= 0.80:
        classification = "text"
    elif valid_share >= 0.10 or printable_ratio >= 0.70:
        classification = "mixed"
    else:
        classification = "binary"

    skipped = False
    if classification == "binary" and skip_bad:
        skipped = True
        if writer is not None:
            writer.close()
            writer = None
        if parquet_path and os.path.exists(parquet_path):
            os.remove(parquet_path)
            parquet_path = None
    else:
        # Flush any remaining rows
        if not parse_only and batch_cols["event_id"]:
            _flush_batch()
        if writer is not None:
            writer.close()
            writer = None

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
    start_offset: int = 0,
    parse_only: bool = False,
    skip_db_sync: bool = False,
    stream_id: int = 0,
    out_base_dir: str = "data/parquet",
    tracker: Any | None = None,
    batch_rows: int = 50_000,
    compression: str = "zstd",
) -> dict[str, Any]:
    """Ingest log files using parallel chunked Parquet writing."""
    if not paths:
        return {"files_ingested": 0, "total_events": 0, "malformed_lines": 0}

    main_path = paths[0]
    if not os.path.exists(main_path):
        raise FileNotFoundError(f"Log file not found: {main_path}")

    num_workers = workers if workers and workers > 0 else getattr(settings, "ingest_workers", 8)
    effective_chunk_size = chunk_size if chunk_size else getattr(settings, "ingest_chunk_size_mb", 64) * 1024 * 1024
    effective_batch_rows = batch_rows if batch_rows else getattr(settings, "ingest_batch_rows", 50_000)
    effective_compression = compression if compression else getattr(settings, "ingest_compression", "zstd")
    manifest_path = os.path.join(out_base_dir, "_manifest.json")

    completed_chunks: dict[int, dict[str, Any]] = {}
    if resume and not parse_only and os.path.exists(manifest_path):
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

    ranges = compute_chunk_ranges(main_path, chunk_size=effective_chunk_size, limit_bytes=limit_bytes, start_offset=start_offset)
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
                    parse_only,
                    effective_batch_rows,
                    effective_compression,
                ): idx
                for (idx, s_byte, e_byte) in tasks_to_run
            }

            if tracker is not None:
                try:
                    tracker.set_worker_pids(list(executor._processes.keys()))
                except Exception:
                    pass

            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                chunk_results.append(res)
                total_processed_bytes += res["bytes"]

                # Report progress every second
                now = time.time()
                if not skip_db_sync and (now - last_update_time >= 1.0 or len(chunk_results) == total_chunks):
                    last_update_time = now
                    pct = round((len(chunk_results) / total_chunks) * 100, 1)
                    try:
                        duck.update_job(job_id, progress_pct=pct)
                    except Exception:
                        pass

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

    if not parse_only:
        os.makedirs(out_base_dir, exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

    # Refresh DuckDB view over the parquet files and update stats if not skipped
    if not parse_only and not skip_db_sync:
        duck.ensure_events_view(out_base_dir)
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
