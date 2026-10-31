"""Streaming log file chunker.

Reads log files one line at a time (never loads the whole file).
Yields chunks of parsed event dicts for bulk insertion.
Counts and skips malformed lines without crashing.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Generator
from pathlib import Path
from typing import Any

from app.pipeline.ingest.parsers import cef, csv_parser, json_parser, syslog


def _sniff_format(path: str) -> str:
    """Return the best-guess log format from the file extension and first line."""
    ext = Path(path).suffix.lower()
    if ext == ".json" or ext == ".jsonl":
        return "json"
    if ext == ".csv":
        return "csv"
    if ext == ".cef":
        return "cef"
    # Read first non-empty line
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                if raw.startswith("{"):
                    return "json"
                if "CEF:" in raw:
                    return "cef"
                break
    except OSError:
        pass
    return "syslog"


def stream_events(
    path: str,
    file_index: int,
    chunk_size: int = 50_000,
) -> Generator[tuple[list[dict[str, Any]], int, int], None, None]:
    """Stream parsed events from *path* as chunks.

    Yields (chunk, malformed_count, total_lines).
    event_id = ev_<file_index>_<byte_offset>
    """
    fmt = _sniff_format(path)
    chunk: list[dict[str, Any]] = []
    malformed = 0
    total_lines = 0
    csv_header: list[str] | None = None

    with open(path, encoding="utf-8", errors="replace") as fh:
        while True:
            byte_offset = fh.tell()
            raw = fh.readline()
            if not raw:
                break
            total_lines += 1
            event_id = f"ev_{file_index}_{byte_offset}"
            try:
                if fmt == "json":
                    ev = json_parser.parse_line(raw, path, event_id)
                elif fmt == "cef":
                    ev = cef.parse_line(raw, path, event_id)
                elif fmt == "csv":
                    if csv_header is None:
                        # First non-empty line is the header
                        line = raw.strip()
                        if line:
                            reader = csv.reader(io.StringIO(line))
                            csv_header = next(reader, [])
                        ev = None
                    else:
                        ev = csv_parser.parse_line(raw, path, event_id, csv_header)
                else:
                    ev = syslog.parse_line(raw, path, event_id)
            except Exception:
                ev = None

            if ev is None:
                malformed += 1
                continue

            chunk.append(ev)
            if len(chunk) >= chunk_size:
                yield chunk, malformed, total_lines
                chunk = []
                malformed = 0

    if chunk:
        yield chunk, malformed, total_lines

