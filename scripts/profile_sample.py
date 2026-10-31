"""Profile ingestion speed on a sample file.

Usage:
    python scripts/profile_sample.py <log_file_path> [--chunk-size 50000]
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.pipeline.ingest.chunker import stream_events


def main():
    parser = argparse.ArgumentParser(description="Profile CaseFile ingest speed")
    parser.add_argument("path", help="Log file to profile")
    parser.add_argument("--chunk-size", type=int, default=50_000)
    args = parser.parse_args()

    t0 = time.perf_counter()
    total_events = 0
    total_malformed = 0
    total_lines = 0
    chunks = 0

    for chunk, malformed, lines in stream_events(args.path, file_index=0, chunk_size=args.chunk_size):
        total_events += len(chunk)
        total_malformed += malformed
        total_lines += lines
        chunks += 1

    elapsed = time.perf_counter() - t0
    file_size_mb = os.path.getsize(args.path) / 1_048_576

    print(f"File size:      {file_size_mb:.1f} MB")
    print(f"Total lines:    {total_lines:,}")
    print(f"Events parsed:  {total_events:,}")
    print(f"Malformed:      {total_malformed:,}")
    print(f"Chunks:         {chunks}")
    print(f"Elapsed:        {elapsed:.2f}s")
    print(f"Throughput:     {file_size_mb / elapsed:.1f} MB/s")
    print(f"Events/sec:     {total_events / elapsed:,.0f}")


if __name__ == "__main__":
    main()

