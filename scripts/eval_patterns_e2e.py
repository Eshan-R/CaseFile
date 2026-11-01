"""End-to-end evaluation of unsupervised pattern discovery subsystem against 9.12M rows."""

import csv
import json
import os
import sys
import time

import psutil

# Ensure backend is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.pipeline.evaluate.evaluator import evaluate_manifest
from app.pipeline.patterns.exporter import (
    export_iocs_csv,
    export_patterns_json,
    export_patterns_yaml,
)
from app.pipeline.patterns.rule_gen import (
    dry_run_rule,
    pattern_to_rule_candidate,
)
from app.pipeline.patterns.runner import run_pattern_mining
from app.pipeline.patterns.tune_report import generate_tuning_report
from app.store import duck


def main():
    proc = psutil.Process()
    print("[*] Starting end-to-end pattern discovery on 9.12M log events...")
    t0 = time.perf_counter()

    # 1. Run pattern mining
    patterns, timings = run_pattern_mining(min_score=3.0, max_patterns=100)
    t_miners = time.perf_counter() - t0
    peak_rss = proc.memory_info().rss / (1024 ** 2)

    print(f"[+] Discovered {len(patterns)} patterns in {t_miners:.2f}s (Peak RSS: {peak_rss:.1f} MB)")
    print(f"    Timings per miner: {json.dumps(timings, indent=2)}")

    # 2. Persist patterns to DuckDB
    duck.save_patterns_batch(patterns)
    print(f"[+] Persisted {len(patterns)} patterns into DuckDB 'patterns' table")

    # 3. Export to JSON, YAML, and CSV
    export_patterns_json(patterns, "data/patterns.json")
    export_patterns_yaml(patterns, "data/patterns.yaml")
    export_iocs_csv(patterns, "data/iocs.csv")
    print("[+] Successfully exported data/patterns.json, data/patterns.yaml, data/iocs.csv")

    # 4. Generate tuning report
    tune_rep = generate_tuning_report(output_path="data/tune_report.json")
    print(f"[+] Successfully generated data/tune_report.json with {len(tune_rep.get('rules', []))} evaluated rules")
    print(f"    Safe rules: {tune_rep.get('safe_rules')}, Noisy rules: {tune_rep.get('noisy_rules')}, Dormant rules: {tune_rep.get('dormant_rules')}")

    # 5. Rule candidate generation & noise guard validation
    print("[*] Testing behavioral rule candidate synthesis and noise guard...")
    approved_rules = []
    rejected_count = 0
    with duck.cursor() as con:
        for p in patterns[:20]:
            rule = pattern_to_rule_candidate(p)
            if not rule:
                continue
            res = dry_run_rule(rule, con)
            if res["passed"]:
                approved_rules.append(rule)
            else:
                rejected_count += 1
    print(f"[+] Sample 20 candidates evaluated: {len(approved_rules)} qualified, {rejected_count} filtered by noise guard")

    # 6. Evaluate against manifest
    manifest_path = "data/firex-30G.log.manifest.json"
    if os.path.exists(manifest_path):
        print(f"[*] Evaluating pattern coverage against ground-truth manifest: {manifest_path}...")
        eval_res = evaluate_manifest(manifest_path)
        cov = eval_res.get("planted_incident_pattern_coverage")
        cov_str = f"{cov * 100:.1f}%" if cov is not None else "NOT MEASURED"
        unmatched = eval_res.get("unmatched_pattern_ratio")
        unmatched_str = f"{unmatched * 100:.1f}%" if unmatched is not None else "NOT MEASURED"
        print(f"[+] Manifest Coverage: {cov_str} ({eval_res.get('total_planted_incidents')} planted incidents)")
        print(f"[+] Unmatched Pattern Ratio: {unmatched_str} (organic background discoveries)")
    else:
        print("[!] Manifest file not found; skipping coverage calculation")

    # 7. Print Top 20 Patterns Summary
    print("\n" + "=" * 90)
    print("TOP 20 DISCOVERED PATTERNS")
    print("=" * 90)
    for idx, p in enumerate(patterns[:20], 1):
        entities_str = ", ".join(p.entities[:3])
        sample_eids = ", ".join(p.example_event_ids[:2])
        print(f"{idx:2d}. [{p.kind:12s}] {p.pattern_id} | Score: {p.score:4.1f} | Supp: {p.support:5d} | {p.suggested_technique or 'N/A'}")
        print(f"    Title   : {p.title}")
        print(f"    Entities: {entities_str}")
        print(f"    Examples: {sample_eids}")
        print("-" * 90)

    # 8. Print Discovered IOCs Summary
    if os.path.exists("data/iocs.csv"):
        with open("data/iocs.csv", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
        print(f"\n[+] Total Discovered IOCs: {len(reader)}")
        print("Sample Top Discovered IOCs:")
        for r in reader[:10]:
            print(f"    - {r['ioc_type']:10s} : {r['ioc_value']:35s} (count: {r['count']}, technique: {r.get('suggested_technique', '')})")

if __name__ == "__main__":
    main()
