"""Single-chunk profiling script using cProfile and sub-step microbenchmarks.

Breaks down single 64 MB chunk processing time across:
1. Line reading / block I/O
2. UTF-8 line decoding
3. Tokenization (parse_kv)
4. Timestamp & timezone conversion
5. Record building & type normalization
6. PyArrow table conversion
7. Parquet serialization to disk (zstd)
"""

from __future__ import annotations

import argparse
import cProfile
import os
import pstats
import shutil
import sys
import tempfile
import time
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

# Ensure backend is on sys.path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BACKEND_DIR = os.path.join(_REPO_ROOT, "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.pipeline.ingest.parsers import fortigate_kv  # noqa: E402
from app.pipeline.ingest.runner import compute_chunk_ranges  # noqa: E402


def profile_single_chunk_breakdown(
    file_path: str,
    start_byte: int,
    end_byte: int,
    stream_id: int = 0,
) -> dict[str, Any]:
    """Measure granular time breakdown for a single chunk."""
    file_name = os.path.basename(file_path)
    bench_dir = r"C:\casefile-bench"
    os.makedirs(bench_dir, exist_ok=True)
    temp_dir = tempfile.mkdtemp(dir=bench_dir, prefix="chunk_prof_")
    pq_path = os.path.join(temp_dir, "test.parquet")

    io_time = 0.0
    decode_time = 0.0
    tokenize_time = 0.0
    timestamp_time = 0.0
    record_build_time = 0.0
    lines = 0
    parsed = 0
    records: list[dict[str, Any]] = []

    t_start = time.perf_counter()

    with open(file_path, "rb") as fh:
        fh.seek(start_byte)
        while True:
            t0 = time.perf_counter()
            if fh.tell() >= end_byte:
                break
            raw_b = fh.readline()
            if not raw_b:
                break
            offset = fh.tell() - len(raw_b)
            t1 = time.perf_counter()
            io_time += (t1 - t0)
            lines += 1

            raw_s = raw_b.decode("utf-8", errors="replace")
            t2 = time.perf_counter()
            decode_time += (t2 - t1)

            # Sub-step profiling within fortigate_kv logic
            # 1. Tokenize
            t_tok0 = time.perf_counter()
            kv = fortigate_kv.parse_kv(raw_s)
            t_tok1 = time.perf_counter()
            tokenize_time += (t_tok1 - t_tok0)

            if not kv:
                continue

            # 2. Timestamp
            t_ts0 = time.perf_counter()
            date_val = kv.get("date")
            time_val = kv.get("time")
            logid_val = kv.get("logid")
            if not date_val or not logid_val:
                continue
            tz_val = kv.get("tz", "+0000")
            offset_sec = fortigate_kv.parse_tz_offset_seconds(tz_val)
            try:
                y = int(date_val[:4])
                m = int(date_val[5:7])
                d = int(date_val[8:10])
                t_str = time_val or "00:00:00"
                hh = int(t_str[:2])
                mm = int(t_str[3:5])
                ss = int(t_str[6:8])
                dt_local = fortigate_kv.datetime(y, m, d, hh, mm, ss)
                dt_utc = dt_local - fortigate_kv.timedelta(seconds=offset_sec)
                _ = dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                continue
            t_ts1 = time.perf_counter()
            timestamp_time += (t_ts1 - t_ts0)

            # 3. Record build via parse_line or dict construction
            t_rb0 = time.perf_counter()
            rec = fortigate_kv.parse_line(raw_s, file_name, offset, stream=stream_id)
            if rec is not None:
                records.append(rec)
                parsed += 1
            t_rb1 = time.perf_counter()
            record_build_time += (t_rb1 - t_rb0)

    # 4. PyArrow Table from pylist
    t_pa0 = time.perf_counter()
    table = pa.Table.from_pylist(records)
    t_pa1 = time.perf_counter()
    arrow_time = t_pa1 - t_pa0

    # 5. Parquet serialization to disk
    t_pq0 = time.perf_counter()
    pq.write_table(
        table,
        pq_path,
        compression="zstd",
        row_group_size=500_000,
        use_dictionary=True,
    )
    t_pq1 = time.perf_counter()
    parquet_time = t_pq1 - t_pq0

    t_total = time.perf_counter() - t_start
    pq_size_bytes = os.path.getsize(pq_path) if os.path.exists(pq_path) else 0

    # Clean up temp
    shutil.rmtree(temp_dir, ignore_errors=True)

    chunk_bytes = end_byte - start_byte
    compression_ratio = round(chunk_bytes / pq_size_bytes, 2) if pq_size_bytes > 0 else 0.0

    return {
        "chunk_bytes": chunk_bytes,
        "lines": lines,
        "parsed": parsed,
        "total_time_s": round(t_total, 3),
        "io_time_s": round(io_time, 3),
        "decode_time_s": round(decode_time, 3),
        "tokenize_time_s": round(tokenize_time, 3),
        "timestamp_time_s": round(timestamp_time, 3),
        "record_build_time_s": round(record_build_time, 3),
        "arrow_time_s": round(arrow_time, 3),
        "parquet_time_s": round(parquet_time, 3),
        "pq_size_bytes": pq_size_bytes,
        "compression_ratio": compression_ratio,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile single chunk ingest performance.")
    parser.add_argument("--log", default=r"C:\casefile-bench\slice1g.log", help="Path to log file")
    parser.add_argument("--append-doc", default="docs/INGEST_TUNING.md", help="Append report to doc")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"Error: log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    ranges = compute_chunk_ranges(args.log, chunk_size=64 * 1024 * 1024, limit_bytes=64 * 1024 * 1024)
    if not ranges:
        print("Error: could not determine chunk ranges", file=sys.stderr)
        sys.exit(1)

    s_byte, e_byte = ranges[0]
    print(f"Profiling 64 MB chunk [byte {s_byte} to {e_byte}]...")

    # 1. Micro-benchmark breakdown
    breakdown = profile_single_chunk_breakdown(args.log, s_byte, e_byte)

    total_s = breakdown["total_time_s"]
    io_pct = round((breakdown["io_time_s"] / total_s) * 100, 1)
    dec_pct = round((breakdown["decode_time_s"] / total_s) * 100, 1)
    tok_pct = round((breakdown["tokenize_time_s"] / total_s) * 100, 1)
    ts_pct = round((breakdown["timestamp_time_s"] / total_s) * 100, 1)
    rb_pct = round((breakdown["record_build_time_s"] / total_s) * 100, 1)
    arr_pct = round((breakdown["arrow_time_s"] / total_s) * 100, 1)
    pq_pct = round((breakdown["parquet_time_s"] / total_s) * 100, 1)

    print("\n--- Microbenchmark Sub-step Breakdown ---")
    print(f"1. Line Reading / I/O:        {breakdown['io_time_s']}s ({io_pct}%)")
    print(f"2. UTF-8 Line Decode:         {breakdown['decode_time_s']}s ({dec_pct}%)")
    print(f"3. Key-Value Tokenization:    {breakdown['tokenize_time_s']}s ({tok_pct}%)")
    print(f"4. Timestamp & TZ Parse:      {breakdown['timestamp_time_s']}s ({ts_pct}%)")
    print(f"5. Record Build & Cast:       {breakdown['record_build_time_s']}s ({rb_pct}%)")
    print(f"6. PyArrow Table from dicts:  {breakdown['arrow_time_s']}s ({arr_pct}%)")
    print(f"7. Parquet Write (zstd):      {breakdown['parquet_time_s']}s ({pq_pct}%)")
    print(f"Total Chunk Time:             {total_s}s ({breakdown['lines']} lines, {round(breakdown['lines']/total_s):,} rows/s)")
    print(f"Parquet Compression Ratio:    {breakdown['compression_ratio']}x ({breakdown['pq_size_bytes'] / (1024*1024):.2f} MB)")

    # 2. cProfile run
    profiler = cProfile.Profile()
    profiler.enable()
    # Run parsing on 20,000 lines for clean call graph
    with open(args.log, "rb") as fh:
        fh.seek(s_byte)
        count = 0
        while count < 20_000:
            line_b = fh.readline()
            if not line_b:
                break
            count += 1
            line_s = line_b.decode("utf-8", errors="replace")
            fortigate_kv.parse_line(line_s, "firex-10G.log", fh.tell(), 0)
    profiler.disable()

    stats = pstats.Stats(profiler)
    stats.sort_stats("cumtime")

    # Format report section
    doc_lines = [
        "",
        "## 7. Single 64 MB Chunk cProfile & Execution Breakdown",
        f"- Chunk Byte Range: `[{s_byte:,} .. {e_byte:,}]` ({round(breakdown['chunk_bytes'] / (1024**2), 2)} MB)",
        f"- Total Lines: {breakdown['lines']:,} | Parsed Records: {breakdown['parsed']:,}",
        f"- Total Chunk Processing Time: **{total_s}s** ({round(breakdown['lines'] / total_s):,} rows/s)",
        f"- Parquet Size: **{breakdown['pq_size_bytes'] / (1024**2):.2f} MB** (Compression Ratio: **{breakdown['compression_ratio']}x**)",
        "",
        "### Sub-Step Microbenchmark Breakdown",
        "| Sub-Step | Time (s) | Share (%) | Optimization Opportunity |",
        "|---|---|---|---|",
        f"| Line Reading / Block I/O | {breakdown['io_time_s']} | {io_pct}% | Sub-block reading (8 MB blocks) |",
        f"| UTF-8 Line Decode | {breakdown['decode_time_s']} | {dec_pct}% | Direct byte-level slicing |",
        f"| Key-Value Tokenizer (`parse_kv`) | {breakdown['tokenize_time_s']} | {tok_pct}% | Fast precompiled regex / split tokenizer |",
        f"| Timestamp & TZ Parsing | {breakdown['timestamp_time_s']} | {ts_pct}% | LRU cache on `(date, time, tz)` strings |",
        f"| Record Build & Normalization | {breakdown['record_build_time_s']} | {rb_pct}% | Columnar list buffers instead of dicts |",
        f"| PyArrow Table Conversion | {breakdown['arrow_time_s']} | {arr_pct}% | Pre-allocated `pa.Table.from_arrays` |",
        f"| Parquet Serialization (zstd) | {breakdown['parquet_time_s']} | {pq_pct}% | Streaming row groups (`ParquetWriter`) |",
        "",
    ]

    if args.append_doc and os.path.exists(args.append_doc):
        with open(args.append_doc, "a", encoding="utf-8") as f:
            f.write("\n".join(doc_lines) + "\n")
        print(f"\nAppended profiling breakdown to {args.append_doc}")
    elif args.append_doc:
        with open(args.append_doc, "w", encoding="utf-8") as f:
            f.write("\n".join(doc_lines) + "\n")
        print(f"\nCreated {args.append_doc} with profiling breakdown")


if __name__ == "__main__":
    main()

