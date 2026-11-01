"""Golden verification test comparing parser outputs against frozen baseline fixture.

Verifies that any optimized parser implementation produces 100% identical outputs
across all fields, edge cases, and malformed inputs without requiring firex-10G.log.
"""

from __future__ import annotations

import gzip
import json
import os

from app.pipeline.ingest.parsers import fortigate_kv


def test_golden_parser_all_cases():
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "golden_sample.json.gz")
    assert os.path.exists(fixture_path), f"Fixture not found: {fixture_path}"

    with gzip.open(fixture_path, "rt", encoding="utf-8") as f:
        samples = json.load(f)

    assert len(samples) >= 15_000, f"Expected at least 15,000 samples, got {len(samples)}"

    mismatches = 0
    first_diff = None

    for idx, item in enumerate(samples):
        raw_s = item["raw"]
        offset = item["offset"]
        stream = item["stream"]
        file_name = item["file_name"]
        expected = item["expected"]

        actual = fortigate_kv.parse_line(raw_s, file_name, offset, stream=stream)

        if expected is None:
            if actual is not None:
                mismatches += 1
                if not first_diff:
                    first_diff = f"Sample #{idx}: Expected None, got {actual}"
        else:
            if actual is None:
                mismatches += 1
                if not first_diff:
                    first_diff = f"Sample #{idx}: Expected dict, got None"
            elif actual != expected:
                mismatches += 1
                if not first_diff:
                    # Find differing keys
                    diff_keys = []
                    for k in set(expected.keys()) | set(actual.keys()):
                        if expected.get(k) != actual.get(k):
                            diff_keys.append(f"{k} (exp: {expected.get(k)!r} vs act: {actual.get(k)!r})")
                    first_diff = f"Sample #{idx} field diffs: {', '.join(diff_keys)}"

        if mismatches > 10:
            break

    assert mismatches == 0, f"Golden test failed with {mismatches} mismatches. First diff: {first_diff}"

