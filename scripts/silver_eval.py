"""CLI Runner for Silver-Standard Independent SQL Evaluation.

Usage:
    python scripts/silver_eval.py [--db data/run.duckdb]

Writes:
    docs/SILVER_EVAL.md
    docs/silver_oracles.json
"""

import argparse
import json
import os
import sys
import time

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.pipeline.evaluate.silver import BANNER, run_silver_eval


def generate_silver_markdown_report(res: dict, output_path: str = "docs/SILVER_EVAL.md") -> str:
    """Generate comprehensive markdown report for silver standard evaluation."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    b_recall_val = res.get("behavior_recall")
    b_recall_str = f"**{b_recall_val * 100:.2f}%** ({res.get('matched_behaviors_count', 0):,} / {res.get('merged_behaviors_count', 0):,})" if b_recall_val is not None else "N/A"
    prec_det_val = res.get("precision_proxy_detection", res.get("precision_proxy"))
    prec_det_str = f"**{prec_det_val * 100:.2f}%** ({res.get('matched_detections', 0):,} / {res.get('total_our_detections', 0):,})" if prec_det_val is not None else "N/A"
    prec_beh_val = res.get("precision_proxy_behavior")
    prec_beh_str = f"**{prec_beh_val * 100:.2f}%** ({res.get('matched_active_behaviors', 0):,} / {res.get('total_active_behaviors', 0):,})" if prec_beh_val is not None else "N/A"

    lines: list[str] = [
        f"> [!IMPORTANT]\n> **{BANNER}**\n",
        "# Silver-Standard Agreement Evaluation Report\n",
        r"- **Dataset Evaluated**: `firex-10G.log` telemetry (clean region $\le 4,815,675,419$ bytes)",
        "- **Evaluation Methodology**: 13 Independent SQL Oracles (Zero detection engine / manifest coupling)",
        f"- **Total Oracle Rows Extracted**: **{res['total_oracle_rows']:,}**",
        f"- **Total Merged Behaviors Extracted**: **{res.get('merged_behaviors_count', 0):,}**",
        f"- **Total Active Detections Evaluated**: **{res['total_our_detections']:,}**",
        f"- **Total Active Behaviors (Collapsed)**: **{res.get('total_active_behaviors', 0):,}**",
        f"- **Behavior Recall (Merged)**: {b_recall_str}",
        f"- **Row Recall (Raw Windows)**: **{res['silver_recall'] * 100:.2f}%** ({res['matched_oracle_rows']:,} / {res['total_oracle_rows']:,})",
        f"- **Precision Proxy (Detection Level)**: {prec_det_str}",
        f"- **Precision Proxy (Behavior Level)**: {prec_beh_str}",
        f"- **Label Accuracy (Exact)**: **{res['label_accuracy_exact'] * 100:.2f}%**" if res['label_accuracy_exact'] is not None else "- **Label Accuracy (Exact)**: N/A",
        f"- **Label Accuracy (Family)**: **{res['label_accuracy_family'] * 100:.2f}%**" if res['label_accuracy_family'] is not None else "- **Label Accuracy (Family)**: N/A",
        f"- **Multi-Class Incidents (>= 2 Oracle Classes)**: **{res['multi_class_incidents']:,}**",
        f"- **Multi-Class Incidents Sharing Entity**: **{res['incident_multi_class_coverage']:,}**",
        f"- **Multi-Class Incidents Ordered by Tactic**: **{res['incident_ordered_coverage']:,}**\n",
        "---\n",
        "## 1. Per-Class Agreement & Metric Distributions\n",
        "| Oracle Class | Oracle Rows | Row Matched | Row Recall | Behaviors | Beh Matched | Beh Recall | Exact Acc | Family Acc | Metric (p50) | Metric (Max) |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]

    for c, st in res.get("per_class", {}).items():
        o_rows = st["oracle_rows"]
        matched = st["matched"]
        recall_str = f"{st['silver_recall'] * 100:.1f}%"
        b_cnt = st.get("behaviors", 0)
        b_mat = st.get("matched_behaviors", 0)
        b_rec_str = f"{st.get('behavior_recall', 0) * 100:.1f}%"
        exact_str = f"{st['label_accuracy_exact'] * 100:.1f}%" if st["label_accuracy_exact"] is not None else "N/A"
        fam_str = f"{st['label_accuracy_family'] * 100:.1f}%" if st["label_accuracy_family"] is not None else "N/A"
        dist = st.get("metric_distribution", {})
        p50 = f"{dist.get('p50')}" if dist.get("p50") is not None else "-"
        mx = f"{dist.get('max')}" if dist.get("max") is not None else "-"
        lines.append(f"| `{c}` | {o_rows:,} | {matched:,} | {recall_str} | {b_cnt:,} | {b_mat:,} | {b_rec_str} | {exact_str} | {fam_str} | {p50} | {mx} |")

    lines.extend([
        "\n---\n",
        "## 2. Suppressed Population Windows\n",
        "> [!NOTE]\n",
        r"> In accordance with Rule 7 (Population Guard), any time window where $\ge 10$ distinct sources trip or $\ge 30\%$ of all active internal hosts trip the same oracle condition simultaneously is flagged as a sensor/network population anomaly and excluded from the accepted answer key." + "\n",
    ])

    suppressed = res.get("suppressed_population_windows", [])
    if suppressed:
        lines.append("| Oracle | Window Start | Duration | Tripping Entities | Status / Reason |")
        lines.append("|---|---|---|---|---|")
        for sup in suppressed:
            tripping = sup.get("tripping_internal_sources") or sup.get("tripping_internal_destinations") or sup.get("tripping_sources") or 0
            dur = f"{sup.get('duration_seconds', 0)}s"
            reason = sup.get("reason") or f"{sup.get('ratio', 0) * 100:.1f}% of active internal hosts"
            lines.append(f"| `{sup.get('oracle_id')}` | {sup.get('window')} | {dur} | {tripping:,} | **SUPPRESSED** ({reason}) |")
    else:
        lines.append("*No population-wide artifact windows were triggered.*\n")

    lines.extend([
        "\n---\n",
        "## 3. Unconfirmed Detections (Precision Proxy)\n",
        "> [!NOTE]\n",
        "> Detections in our database that did not match an independent SQL oracle row. These represent a precision proxy and are **unconfirmed detections**, NOT ground-truth false alarms (since oracles cover specific behavioral patterns, not the entire detection rule surface).\n",
        "| Rule ID | Unconfirmed Firing Count |",
        "|---|---|",
    ])

    unconfirmed = res.get("unconfirmed_detections_by_rule", {})
    if unconfirmed:
        for r_id, cnt in list(unconfirmed.items())[:20]:
            lines.append(f"| `{r_id}` | {cnt:,} |")
        if len(unconfirmed) > 20:
            rem = sum(list(unconfirmed.values())[20:])
            lines.append(f"| *... {len(unconfirmed) - 20} other rules* | {rem:,} |")
    else:
        lines.append("| *None* | 0 |")

    lines.extend([
        "\n---\n",
        "## 4. Missed Oracle Rows (Top Opportunities for Detection Tuning)\n",
        "| # | Oracle ID | Expected Technique | Tactic | Entity | Window Start | Window End | Metric | Sample Evidence Event IDs |",
        "|---|---|---|---|---|---|---|---|---|",
    ])

    missed = res.get("missed_oracle_rows", [])
    if missed:
        for i, m in enumerate(missed[:20], 1):
            ent = m.get("src_ip") or m.get("dst_ip") or m.get("user") or "N/A"
            eids = "<br>".join(m.get("evidence_event_ids", [])[:2])
            lines.append(f"| {i} | `{m['oracle_id']}` | `{m['expected_technique']}` | {m['expected_tactic']} | `{ent}` | {m['t_start']} | {m['t_end']} | {m['metric']} | {eids} |")
    else:
        lines.append("| - | *All oracle rows matched* | - | - | - | - | - | - | - |")

    lines.extend([
        "\n---\n",
        "## 5. Confusion List (Active Detections vs Matched Oracle Expectations)\n",
        "| Oracle Class | Expected Technique | Emitted Technique | Firing Count |",
        "|---|---|---|---|",
    ])

    confusion = res.get("confusion_list", [])
    if confusion:
        for item in confusion[:30]:
            lines.append(f"| `{item['oracle_class']}` | `{item['expected_technique']}` | `{item['emitted_technique']}` | {item['count']:,} |")
    else:
        lines.append("| - | *No technique confusions (100% exact match)* | - | 0 |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_path


def main():
    parser = argparse.ArgumentParser(description="CaseFile Silver-Standard Independent Evaluator")
    parser.add_argument("--db", type=str, default=None, help="Path to DuckDB database (default: data/casefile.duckdb or in-process)")
    args = parser.parse_args()

    print("\n" + "=" * 90)
    print(BANNER)
    print("=" * 90)

    db_path = args.db
    if db_path and not os.path.exists(db_path):
        print(f"[!] ERROR: Target database file does not exist: {db_path}")
        print("    - To evaluate the active development database, omit --db or use: --db data/casefile.duckdb")
        print("    - If evaluating a pipeline run, run 'python scripts/run_all.py' first to generate data/run.duckdb.")
        return 1

    t0 = time.perf_counter()
    res = run_silver_eval(db_path=db_path)
    elapsed = time.perf_counter() - t0

    # Write output files
    md_path = generate_silver_markdown_report(res, "docs/SILVER_EVAL.md")
    json_path = "docs/silver_oracles.json"
    os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)

    print(f"\n[+] Silver evaluation finished in {elapsed:.2f}s")
    print(f"[+] Output written to: {md_path} and {json_path}\n")

    # Final 10-line summary to console
    print("-" * 90)
    print("SILVER EVALUATION SUMMARY (Agreement, Not True Accuracy)")
    print("-" * 90)
    b_rec_pct = res.get("behavior_recall", 0.0) * 100.0
    print(f"Total Behaviors: {res.get('merged_behaviors_count', 0):,} | Matched: {res.get('matched_behaviors_count', 0):,} | Behavior Recall: {b_rec_pct:.1f}%")
    print(f"Total Oracle Rows: {res['total_oracle_rows']:,} | Matched: {res['matched_oracle_rows']:,} | Row Recall: {res['silver_recall']*100:.1f}%")
    exact_acc_str = f"{res['label_accuracy_exact']*100:.1f}%" if res['label_accuracy_exact'] is not None else "N/A"
    fam_acc_str = f"{res['label_accuracy_family']*100:.1f}%" if res['label_accuracy_family'] is not None else "N/A"
    prec_det = res.get("precision_proxy_detection", res.get("precision_proxy", 0.0)) * 100.0
    prec_beh = res.get("precision_proxy_behavior", 0.0) * 100.0
    print(f"Label Accuracy: Exact: {exact_acc_str} | Family: {fam_acc_str}")
    print(f"Precision Proxy: Detection-level: {prec_det:.1f}% | Behavior-level: {prec_beh:.1f}%")
    print(f"Multi-Class Incidents: {res['multi_class_incidents']:,} | Entity-Shared: {res['incident_multi_class_coverage']:,} | Tactic-Ordered: {res['incident_ordered_coverage']:,}")
    print(f"Suppressed Population Windows: {len(res['suppressed_population_windows'])}")

    # Oracle rows and recall per class
    print("\nRecall per Oracle Class (Rows & Behaviors):")
    for c, st in res.get("per_class", {}).items():
        b_cnt = st.get("behaviors", 0)
        b_mat = st.get("matched_behaviors", 0)
        b_pct = st.get("behavior_recall", 0.0) * 100.0
        print(f"  - {c:25s}: Rows: {st['matched']:3d}/{st['oracle_rows']:3d} ({st['silver_recall']*100:5.1f}%) | Beh: {b_mat:2d}/{b_cnt:2d} ({b_pct:5.1f}%)")

    # Top 5 missed oracle rows
    print("\nTop 5 Missed Oracle Rows:")
    missed = res.get("missed_oracle_rows", [])
    if missed:
        for i, m in enumerate(missed[:5], 1):
            ent = m.get("src_ip") or m.get("dst_ip") or m.get("user") or "N/A"
            print(f"  {i}. [{m['oracle_id']}] {ent} ({m['expected_technique']} | {m['expected_tactic']}) at {m['t_start']}")
    else:
        print("  None (100% agreement achieved across all classes)")
    print("-" * 90)
    return 0


if __name__ == "__main__":
    sys.exit(main())
