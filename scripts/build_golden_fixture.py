"""Extract ~20,000 diverse sample lines across firex-10G.log and freeze baseline parsed output.

Creates backend/tests/fixtures/golden_sample.json.gz (< 5 MB) containing raw input strings
alongside baseline parsed outputs for standalone verification without requiring the full log file.
"""

from __future__ import annotations

import gzip
import json
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BACKEND_DIR = os.path.join(_REPO_ROOT, "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.pipeline.ingest.parsers import fortigate_kv  # noqa: E402


def sample_block(fh, start_byte: int, target_count: int, file_name: str) -> list[dict]:
    fh.seek(start_byte)
    if start_byte > 0:
        fh.readline()  # Align to line boundary
    
    samples = []
    while len(samples) < target_count:
        offset = fh.tell()
        raw_b = fh.readline()
        if not raw_b:
            break
        raw_s = raw_b.decode("utf-8", errors="replace")
        expected = fortigate_kv.parse_line(raw_s, file_name, offset, stream=0)
        samples.append({
            "raw": raw_s,
            "offset": offset,
            "stream": 0,
            "file_name": file_name,
            "expected": expected,
        })
    return samples


def main():
    log_path = os.path.join(_REPO_ROOT, "data", "firex-10G.log")
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        sys.exit(1)

    file_size = os.path.getsize(log_path)
    file_name = "firex-10G.log"
    print(f"Sampling from {log_path} ({file_size:,} bytes)...")

    all_samples: list[dict] = []

    with open(log_path, "rb") as fh:
        # 1. Start of file (5,000 lines)
        print("Sampling 5,000 lines from start of file...")
        start_samples = sample_block(fh, 0, 5000, file_name)
        all_samples.extend(start_samples)

        # 2. Middle of file (5,000 lines)
        mid_byte = file_size // 2
        print(f"Sampling 5,000 lines from midpoint (~{mid_byte:,} bytes)...")
        mid_samples = sample_block(fh, mid_byte, 5000, file_name)
        all_samples.extend(mid_samples)

        # 3. Corrupted tail region (5,000 lines)
        tail_byte = max(0, file_size - 150_000_000)
        print(f"Sampling 5,000 lines from tail region (~{tail_byte:,} bytes)...")
        tail_samples = sample_block(fh, tail_byte, 5000, file_name)
        all_samples.extend(tail_samples)

        # 4. Filtered edge cases across file (4,800 lines with escapes, quotes, non-ascii, CRLF)
        print("Scanning for edge-case lines across file...")
        edge_samples = []
        scan_positions = [
            file_size // 4,
            (file_size // 4) * 3,
            file_size - 300_000_000,
        ]
        for pos in scan_positions:
            fh.seek(pos)
            fh.readline()
            while len(edge_samples) < 4800:
                offset = fh.tell()
                raw_b = fh.readline()
                if not raw_b:
                    break
                raw_s = raw_b.decode("utf-8", errors="replace")
                # Keep lines with quotes, backslashes, non-ascii, or crlf
                if ('\\"' in raw_s or '\\\\' in raw_s or any(ord(c) > 127 for c in raw_s) or '\r\n' in raw_s or 'msg=' in raw_s):
                    expected = fortigate_kv.parse_line(raw_s, file_name, offset, stream=0)
                    edge_samples.append({
                        "raw": raw_s,
                        "offset": offset,
                        "stream": 0,
                        "file_name": file_name,
                        "expected": expected,
                    })
                    if len(edge_samples) >= 4800:
                        break
        all_samples.extend(edge_samples)

    # 5. Explicit Synthetic Edge Cases (Amendment 4)
    print("Adding explicit synthetic edge cases...")
    synthetic_cases = [
        # Token without '=' mid-line
        'date=2026-10-23 time=08:48:26 logid="0100032001" somerandomtoken srcip=10.0.0.1 action="accept"',
        # 'key=' with empty value at the end
        'date=2026-10-23 time=08:48:26 logid="0100032001" emptykey=',
        # Duplicate keys (last wins)
        'date=2026-10-23 time=08:48:26 logid="0100032001" action="deny" action="accept"',
        # Unterminated quote
        'date=2026-10-23 time=08:48:26 logid="0100032001" msg="unterminated quote here',
        # Escaped quotes and backslashes
        'date=2026-10-23 time=08:48:26 logid="0100032001" msg="hello \\"world\\" and C:\\\\path\\\\file"',
        # Tab separators
        'date=2026-10-23\ttime=08:48:26\tlogid="0100032001"\tsrcip=10.0.0.1',
        # CRLF
        'date=2026-10-23 time=08:48:26 logid="0100032001" srcip=10.0.0.1\r\n',
        # Final line without newline
        'date=2026-10-23 time=08:48:26 logid="0100032001" srcip=10.0.0.1',
        # Malformed lacking date=
        'time=08:48:26 logid="0100032001" srcip=10.0.0.1',
        # Malformed lacking logid=
        'date=2026-10-23 time=08:48:26 srcip=10.0.0.1',
        # Random non-ASCII binary payload
        '\x00\x01\x02\xff\xfe\xfd random binary garbage text here without kv pairs',
        # Quotes with spaces inside value
        'date=2026-10-23 time=08:48:26 logid="0100032001" msg="Multiple words in quote string" status="failed"',
        # Empty string
        '',
    ]
    for i, syn_raw in enumerate(synthetic_cases, 1):
        expected = fortigate_kv.parse_line(syn_raw, file_name, 999000 + i, stream=0)
        all_samples.append({
            "raw": syn_raw,
            "offset": 999000 + i,
            "stream": 0,
            "file_name": file_name,
            "expected": expected,
        })

    fixture_dir = os.path.join(_BACKEND_DIR, "tests", "fixtures")
    os.makedirs(fixture_dir, exist_ok=True)
    fixture_path = os.path.join(fixture_dir, "golden_sample.json.gz")

    print(f"Total samples collected: {len(all_samples):,}. Writing to {fixture_path}...")
    json_bytes = json.dumps(all_samples).encode("utf-8")
    with gzip.open(fixture_path, "wb", compresslevel=9) as gz_out:
        gz_out.write(json_bytes)

    gz_size = os.path.getsize(fixture_path)
    print(f"Fixture written successfully: {gz_size:,} bytes ({gz_size / (1024 * 1024):.2f} MB).")
    if gz_size > 5 * 1024 * 1024:
        print("WARNING: Fixture exceeds 5 MB limit!")
        sys.exit(1)
    print("Done.")


if __name__ == "__main__":
    main()
