"""Profile detection rules SQL execution on full 9.12M row dataset using read-only view.

Never writes to data/casefile.duckdb or data/parquet.
Never calls boost_multi_tactic_confidences().
"""

from __future__ import annotations

import glob
import os
import sys
import tempfile
import time
from typing import Any

import duckdb

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BACKEND_DIR = os.path.join(_REPO_ROOT, "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.pipeline.detect.engine import compile_rule_to_sql  # noqa: E402
from app.pipeline.detect.rule_loader import load_rules  # noqa: E402


def main():
    print("=== Rule Profiling on Full Dataset (Read-Only) ===")
    parquet_glob = os.path.abspath(os.path.join(_REPO_ROOT, "data", "parquet", "stream=*/*/*.parquet")).replace("\\", "/")
    matches = glob.glob(parquet_glob)
    if not matches:
        print(f"No parquet files found matching {parquet_glob}")
        sys.exit(1)

    print(f"Found {len(matches)} parquet chunk files.")

    # Isolated temporary database
    temp_dir = tempfile.mkdtemp(prefix="casefile_rule_prof_")
    db_path = os.path.join(temp_dir, "temp_rules.duckdb")

    con = duckdb.connect(db_path)
    con.execute(
        f"CREATE VIEW events AS "
        f"SELECT * EXCLUDE (timestamp), timestamp, TRY_CAST(timestamp AS TIMESTAMPTZ) AS ts "
        f"FROM read_parquet('{parquet_glob}', union_by_name=True)"
    )

    total_events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"Events view active with {total_events:,} events.")

    # Fetch valid columns
    cols = {r[0].lower() for r in con.execute("DESCRIBE events").fetchall()}
    cols.update({"user", "host", "ts", "timestamp", "event_id"})

    rules = load_rules()
    print(f"Loaded {len(rules)} detection rules. Profiling individual SQL execution...\n")

    rule_timings: list[dict[str, Any]] = []

    for idx, rule in enumerate(rules, 1):
        if not rule.enabled:
            continue
        sql = compile_rule_to_sql(rule, cols)
        if not sql:
            print(f"[{idx:02d}/{len(rules)}] Rule '{rule.id}': Compilation skipped (missing columns)")
            continue

        t0 = time.perf_counter()
        try:
            res = con.execute(sql).fetchall()
            elapsed = time.perf_counter() - t0
            match_count = len(res)
            print(f"[{idx:02d}/{len(rules)}] Rule '{rule.id:<28}' ({rule.type:<9}): {elapsed:>6.3f}s | {match_count:>6,} matches")
            rule_timings.append({
                "rule_id": rule.id,
                "name": rule.name,
                "type": rule.type,
                "technique": rule.technique_id,
                "tactic": rule.tactic,
                "runtime_sec": round(elapsed, 4),
                "matches": match_count,
                "status": "OK",
            })
        except Exception as e:
            elapsed = time.perf_counter() - t0
            print(f"[{idx:02d}/{len(rules)}] Rule '{rule.id}': ERROR in {elapsed:.3f}s: {e}")
            rule_timings.append({
                "rule_id": rule.id,
                "name": rule.name,
                "type": rule.type,
                "technique": rule.technique_id,
                "tactic": rule.tactic,
                "runtime_sec": round(elapsed, 4),
                "matches": 0,
                "status": f"ERROR: {e}",
            })

    # Sort rules by execution time descending
    rule_timings.sort(key=lambda x: x["runtime_sec"], reverse=True)

    print("\n" + "=" * 80)
    print("                      TOP 5 SLOWEST DETECTION RULES")
    print("=" * 80)
    print(f"{'Rank':<5} {'Rule ID':<30} {'Type':<12} {'Runtime (s)':<14} {'Matches'}")
    print("-" * 80)
    for i, r in enumerate(rule_timings[:5], 1):
        print(f"{i:<5} {r['rule_id']:<30} {r['type']:<12} {r['runtime_sec']:>8.3f}s     {r['matches']:>8,}")
    print("=" * 80)

    # Save to temp report file
    temp_report_path = os.path.join(temp_dir, "rule_timing_report.json")
    with open(temp_report_path, "w", encoding="utf-8") as f:
        import json
        json.dump(rule_timings, f, indent=2)

    con.close()
    try:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass

    return rule_timings


if __name__ == "__main__":
    main()

