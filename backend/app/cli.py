"""Typer CLI for CaseFile – run analysis without the HTTP server."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="casefile", help="CaseFile security log analysis CLI.")
console = Console()


@app.command()
def ingest(
    paths: list[Path] = typer.Argument(..., help="Log file paths to ingest"),
    workers: int | None = typer.Option(None, "--workers", "-w", help="Worker processes"),
    resume: bool = typer.Option(False, "--resume", help="Skip finished chunks via _manifest.json"),
    skip_bad: bool = typer.Option(False, "--skip-bad", help="Skip binary/corrupted chunks"),
    limit_bytes: int | None = typer.Option(None, "--limit-bytes", help="Ingest only up to N bytes"),
    chunk_size: int = typer.Option(64 * 1024 * 1024, "--chunk-size", "-c", help="Bytes per chunk"),
) -> None:
    """Stream log files into DuckDB via parallel Parquet chunks."""
    from app.pipeline.ingest.runner import run_ingest
    from app.store.duck import init_db

    init_db()
    str_paths = [str(p) for p in paths]
    console.print(f"Ingesting {len(str_paths)} file(s)...")
    result = run_ingest(
        job_id="cli",
        paths=str_paths,
        chunk_size=chunk_size,
        workers=workers,
        resume=resume,
        skip_bad=skip_bad,
        limit_bytes=limit_bytes,
    )
    console.print_json(json.dumps(result))


@app.command()
def analyse() -> None:
    """Run detection engine and incident linker on ingested data."""
    from app.pipeline.detect.engine import run_detection
    from app.pipeline.detect.rule_loader import load_rules
    from app.pipeline.link.incidents import build_incidents
    from app.store.duck import init_db

    init_db()
    console.print("Loading rules…")
    rules = load_rules()
    console.print(f"  {len(rules)} rules loaded.")

    console.print("Running detection…")
    det_result = run_detection(rules, "cli")
    console.print_json(json.dumps(det_result))

    console.print("Building incidents…")
    inc_result = build_incidents()
    console.print_json(json.dumps(inc_result))


@app.command()
def incidents() -> None:
    """List all incidents in the database."""
    from app.store.duck import init_db, list_incidents

    init_db()
    total, rows = list_incidents(limit=100)
    table = Table(title=f"Incidents ({total} total)")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Techniques")
    table.add_column("First seen")
    for row in rows:
        techs = json.loads(row["techniques"]) if isinstance(row["techniques"], str) else row["techniques"]
        table.add_row(
            row["incident_id"],
            row["title"][:50],
            str(row["severity"]),
            ", ".join(techs[:3]),
            str(row["first_seen"])[:19],
        )
    console.print(table)


@app.command()
def diagnose(
    path: Path = typer.Argument(Path("data/firex-10G.log"), help="Log file path to diagnose"),
    docs_dir: Path = typer.Option(Path("docs"), "--docs-dir", help="Directory to write markdown reports"),
) -> None:
    """Analyze ingested Parquet data and generate integrity, examples, and noise reports."""
    from app.pipeline.diagnose.diagnostics import run_diagnostics

    console.print(f"Running diagnostics on {path}...")
    res = run_diagnostics(log_path=str(path), docs_dir=str(docs_dir))
    console.print(f"[green]Integrity report:[/green] {res['integrity_report']}")
    console.print(f"[green]Full line examples:[/green] {res['full_line_examples']}")
    console.print(f"[green]Noise profile:[/green] {res['noise_profile']}")
    console.print(f"[green]Wall-clock offset:[/green] {res['time_offset_seconds']}s")


@app.command()
def evaluate(
    manifest: Path = typer.Option(..., "--manifest", "-m", help="Path to ground truth manifest (*.manifest.json)"),
    log_file: Path | None = typer.Option(None, "--log-file", help="Path to log file for byte check"),
) -> None:
    """Score detections and incidents against ground-truth manifest."""
    from app.pipeline.evaluate.evaluator import evaluate_manifest

    res = evaluate_manifest(str(manifest), log_file_path=str(log_file) if log_file else None)

    table = Table(title=f"Evaluation against {res['manifest']}")
    table.add_column("Metric", style="bold")
    table.add_column("Result", justify="right")
    table.add_column("Target (Pass)", justify="right")
    table.add_column("Target (Great)", justify="right")
    table.add_column("Status", justify="center")

    def format_pct(val):
        return f"{val * 100:.1f}%" if val is not None else "null"

    det_rate = res["detection_rate"]
    st_det = "[green]PASS[/green]" if det_rate and det_rate >= 0.70 else "[red]FAIL[/red]" if det_rate else "[yellow]null[/yellow]"
    table.add_row("Detection Rate (Steps)", format_pct(det_rate), "70.0%", "90.0%", st_det)

    inc_det = res["incident_detection_rate"]
    table.add_row("Incident Detection Rate", format_pct(inc_det), "70.0%", "90.0%", "-")

    lbl_ex = res["label_accuracy_exact"]
    st_lbl = "[green]PASS[/green]" if lbl_ex and lbl_ex >= 0.60 else "[red]FAIL[/red]" if lbl_ex else "[yellow]null[/yellow]"
    table.add_row("Label Accuracy (Exact)", format_pct(lbl_ex), "60.0%", "85.0%", st_lbl)

    lbl_fam = res["label_accuracy_family"]
    table.add_row("Label Accuracy (Family)", format_pct(lbl_fam), "60.0%", "85.0%", "-")

    p_rate = res["path_rate"]
    st_p = "[green]PASS[/green]" if p_rate and p_rate >= 0.50 else "[red]FAIL[/red]" if p_rate else "[yellow]null[/yellow]"
    table.add_row("Path Rate (Chains & Steps)", format_pct(p_rate), "50.0%", "100.0%", st_p)

    fa_rate = res["false_alarm_rate"]
    st_fa = "[green]PASS[/green]" if fa_rate is not None and fa_rate <= 0.30 else "[red]FAIL[/red]" if fa_rate is not None else "[yellow]null[/yellow]"
    table.add_row("False Alarm Rate", format_pct(fa_rate), "< 30.0%", "< 10.0%", st_fa)

    console.print(table)

    missed = res.get("missed_incidents", [])
    if missed:
        m_table = Table(title=f"Missed Planted Incidents ({len(missed)})")
        m_table.add_column("ID", justify="right")
        m_table.add_column("Name")
        m_table.add_column("Class")
        m_table.add_column("Planted Steps")
        for m in missed[:20]:
            m_table.add_row(str(m["id"]), m["name"], m["class"], str(m["planted_steps"]))
        console.print(m_table)

    top_fa = res.get("top_false_alarms", [])
    if top_fa:
        fa_table = Table(title=f"Top False Alarm Incidents ({len(top_fa)})")
        fa_table.add_column("Incident ID")
        fa_table.add_column("Title")
        fa_table.add_column("Severity")
        fa_table.add_column("Techniques")
        for fa in top_fa:
            techs = json.loads(fa["techniques"]) if isinstance(fa.get("techniques"), str) else fa.get("techniques", [])
            fa_table.add_row(fa["incident_id"], fa["title"][:50], str(fa["severity"]), ", ".join(techs[:3]))
        console.print(fa_table)


@app.command()
def tune_report(
    manifest: Path = typer.Option(..., "--manifest", "-m", help="Path to ground truth manifest"),
) -> None:
    """Report per-rule hit counts vs false alarm counts to guide rule tuning."""
    from app.pipeline.evaluate.evaluator import evaluate_manifest

    res = evaluate_manifest(str(manifest))
    rule_stats = res.get("rule_stats", {})

    table = Table(title="Rule Precision & False Alarm Report")
    table.add_column("Rule ID", style="bold")
    table.add_column("Hits", justify="right")
    table.add_column("False Alarms", justify="right")
    table.add_column("Precision", justify="right")

    for r_id, stats in sorted(rule_stats.items(), key=lambda x: x[1]["false_alarms"], reverse=True):
        hits = stats["hits"]
        fa = stats["false_alarms"]
        prec = f"{(hits / (hits + fa)) * 100:.1f}%" if (hits + fa) > 0 else "N/A"
        table.add_row(r_id, str(hits), str(fa), prec)

    console.print(table)


@app.command()
def reset() -> None:
    """Drop and recreate all database tables."""
    from app.store.duck import reset_all

    typer.confirm("This will delete ALL data. Continue?", abort=True)
    reset_all()
    console.print("[green]Database reset.[/green]")


@app.command()
def stats() -> None:
    """Show aggregate statistics."""
    from app.store.duck import count_events, get_stat, init_db, list_detections, list_incidents

    init_db()
    total_events = count_events()
    total_dets, _ = list_detections(limit=0)
    total_incs, _ = list_incidents(limit=0)
    console.print(f"Events:      {total_events}")
    console.print(f"Detections:  {total_dets}")
    console.print(f"Incidents:   {total_incs}")
    console.print(f"Last ingest: {get_stat('last_ingest_events')} events, "
                  f"{get_stat('last_ingest_malformed')} malformed")


if __name__ == "__main__":
    app()

