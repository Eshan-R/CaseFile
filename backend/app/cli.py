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
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind network interface"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
) -> None:
    """Start the CaseFile web server and UI."""
    import os
    import sys

    import uvicorn

    from app.config import settings

    backend_dir = Path(__file__).resolve().parent.parent
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    duck_path_abs = os.path.abspath(settings.duck_path)
    parquet_dir_abs = os.path.abspath(settings.parquet_dir)
    console.print(f"[bold green]Starting CaseFile server on http://{host}:{port}[/bold green]")
    console.print(f"  [cyan]DUCK_PATH[/cyan]   : {duck_path_abs}")
    console.print(f"  [cyan]PARQUET_DIR[/cyan] : {parquet_dir_abs}")

    uvicorn.run("app.main:app", host=host, port=port, reload=False)


@app.command()
def run(
    log: Path = typer.Argument(..., help="Path to input security log file"),
    manifest: Path | None = typer.Argument(None, help="Path to ground-truth manifest file"),
    skip_eval: bool = typer.Option(False, "--skip-eval", help="Skip manifest evaluation"),
    silver: bool = typer.Option(False, "--silver", help="Run silver-standard evaluation"),
    skip_patterns: bool = typer.Option(False, "--skip-patterns", help="Skip pattern discovery"),
    limit_bytes: int | None = typer.Option(None, "--limit-bytes", help="Limit maximum bytes read"),
    db: str = typer.Option("data/run.duckdb", "--db", help="Target DuckDB file path"),
    reset_dev: bool = typer.Option(False, "--reset-dev", help="Allow resetting dev database"),
    serve: bool = typer.Option(False, "--serve", help="Launch web server after run"),
    port: int = typer.Option(8000, "--port", help="Port for server if --serve is set"),
) -> None:
    """Run end-to-end CaseFile demonstration, benchmarks, and scorecard evaluation."""
    import subprocess
    import sys

    # Locate scripts/run_all.py relative to repo root
    repo_root = Path(__file__).resolve().parent.parent.parent
    run_all_py = repo_root / "scripts" / "run_all.py"
    if not run_all_py.exists():
        run_all_py = Path("scripts/run_all.py").resolve()

    cmd = [sys.executable, str(run_all_py), str(log)]
    if manifest:
        cmd.append(str(manifest))
    if skip_eval:
        cmd.append("--skip-eval")
    if silver:
        cmd.append("--silver")
    if skip_patterns:
        cmd.append("--skip-patterns")
    if limit_bytes:
        cmd.extend(["--limit-bytes", str(limit_bytes)])
    if db:
        cmd.extend(["--db", db])
    if reset_dev:
        cmd.append("--reset-dev")
    if serve:
        cmd.append("--serve")
    if port != 8000:
        cmd.extend(["--port", str(port)])

    ret = subprocess.run(cmd)
    if ret.returncode != 0:
        raise typer.Exit(code=ret.returncode)


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
def detect(
    max_workers: int = typer.Option(2, "--workers", "-w", help="Parallel detection workers"),
    rules_dir: Path = typer.Option(Path("rules"), "--rules-dir", "-d", help="Rules folder"),
) -> None:
    """Run set-based SQL detection rules on ingested data."""
    from app.pipeline.detect.engine import run_detection
    from app.pipeline.detect.rule_loader import load_rules
    from app.store.duck import init_db

    init_db()
    console.print(f"Loading rules from {rules_dir}...")
    rules = load_rules(rules_dir=str(rules_dir))
    console.print(f"  {len(rules)} rules loaded.")
    console.print("Running detection...")
    det_result = run_detection(rules, "cli", max_workers=max_workers)
    console.print_json(json.dumps(det_result))


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

    console.print("Precomputing reach analysis into incident_next…")
    from app.pipeline.path.reach.service import precompute_all_incidents
    reach_res = precompute_all_incidents()
    console.print(f"  Precomputed reach for {reach_res.get('precomputed', 0)} incidents.")


@app.command()
def reach(
    incident_id: str | None = typer.Option(None, "--incident", "-i", help="Specific incident ID to inspect"),
    engine: str = typer.Option("networkx", "--engine", "-e", help="Reach engine (networkx, neo4j)"),
) -> None:
    """Precompute and inspect predictive attack paths and reachability for incidents."""
    from app.pipeline.path.reach.service import (
        precompute_all_incidents,
        precompute_reach_for_incident,
    )
    from app.store.duck import init_db

    init_db()
    if incident_id:
        console.print(f"Precomputing reach for incident {incident_id} with engine={engine}...")
        res = precompute_reach_for_incident(incident_id, engine_name=engine)
        console.print_json(res.model_dump_json())
    else:
        console.print(f"Precomputing reach for all incidents with engine={engine}...")
        summary = precompute_all_incidents(engine_name=engine)
        console.print_json(json.dumps(summary))


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
def stories(
    incident_id: str | None = typer.Option(None, "--incident", "-i", help="Generate story for a specific incident"),
    limit: int = typer.Option(5, "--limit", "-l", help="Number of incidents to generate stories for"),
) -> None:
    """Generate and verify grounded attack stories for incidents."""
    from app.pipeline.report.facts import build_incident_facts
    from app.pipeline.report.verifier import generate_and_verify_story
    from app.store import duck

    duck.init_db()
    if incident_id:
        inc_ids = [incident_id]
    else:
        with duck.cursor() as con:
            rows = con.execute(
                "SELECT incident_id FROM incidents WHERE status='open' ORDER BY risk_score DESC LIMIT ?",
                [limit],
            ).fetchall()
            if not rows:
                rows = con.execute(
                    "SELECT incident_id FROM incidents ORDER BY severity DESC LIMIT ?",
                    [limit],
                ).fetchall()
        inc_ids = [r[0] for r in rows]

    if not inc_ids:
        console.print("[yellow]No incidents found. Run 'casefile analyse' or 'casefile run' first.[/yellow]")
        return

    table = Table(title=f"Generated Attack Stories ({len(inc_ids)} incidents)")
    table.add_column("Incident ID", style="cyan")
    table.add_column("Source", style="magenta")
    table.add_column("Headline")
    table.add_column("Steps", justify="right")
    table.add_column("Actions", justify="right")

    for inc_id in inc_ids:
        try:
            facts = build_incident_facts(inc_id)
            story = generate_and_verify_story(facts)
            duck.save_incident_story(
                inc_id,
                story.model_dump_json(),
                story.story_source,
                facts.facts_sha256,
                story.generated_at,
            )
            source_badge = getattr(story, "source", None) or story.story_source
            table.add_row(
                inc_id,
                source_badge,
                story.headline[:50],
                str(len(story.steps)),
                str(len(story.recommended_actions)),
            )
        except Exception as exc:
            table.add_row(inc_id, "[red]error[/red]", str(exc)[:50], "-", "-")

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


# ---------------------------------------------------------------------------
# Rules Subcommands
# ---------------------------------------------------------------------------
rules_app = typer.Typer(name="rules", help="Manage and validate detection rules.")


@rules_app.command("list")
def rules_list(
    rules_dir: Path = typer.Option(Path("rules"), "--rules-dir", "-d", help="Path to rules folder"),
    all_rules: bool = typer.Option(False, "--all", "-a", help="Include disabled rules"),
) -> None:
    """List loaded detection rules."""
    from app.pipeline.detect.rule_loader import load_rules

    rules = load_rules(rules_dir=str(rules_dir), include_disabled=all_rules)
    table = Table(title=f"Detection Rules ({len(rules)} loaded)")
    table.add_column("Rule ID", style="bold cyan")
    table.add_column("Name")
    table.add_column("Type", style="magenta")
    table.add_column("Technique", style="yellow")
    table.add_column("Tactic", style="green")
    table.add_column("Severity", justify="right")
    table.add_column("Enabled", justify="center")
    for r in rules:
        table.add_row(
            r.id,
            r.name,
            r.type,
            r.technique_id,
            r.tactic,
            str(r.severity),
            "[green]Yes[/green]" if r.enabled else "[red]No[/red]",
        )
    console.print(table)


@rules_app.command("validate")
def rules_validate(
    rules_dir: Path = typer.Option(Path("rules"), "--rules-dir", "-d", help="Path to rules folder"),
) -> None:
    """Validate all rules/*.yaml files and report errors with file and line."""
    from app.pipeline.detect.rule_loader import validate_rules

    res = validate_rules(rules_dir=str(rules_dir))
    if res["valid"]:
        console.print(f"[green]SUCCESS:[/green] All {res['total_rules']} rules are valid.")
    else:
        console.print(f"[red]VALIDATION ERRORS FOUND ({len(res['errors'])} errors):[/red]")
        for err in res["errors"]:
            console.print(f"  - {err}")
        raise typer.Exit(code=1)


@rules_app.command("show")
def rules_show(
    rule_id: str = typer.Argument(..., help="Rule ID to inspect"),
    rules_dir: Path = typer.Option(Path("rules"), "--rules-dir", "-d", help="Path to rules folder"),
) -> None:
    """Show details and configuration for a single detection rule."""
    from app.pipeline.detect.rule_loader import get_rule

    rule = get_rule(rule_id, rules_dir=str(rules_dir))
    if not rule:
        console.print(f"[red]Error:[/red] Rule '{rule_id}' not found in {rules_dir}.")
        raise typer.Exit(code=1)
    console.print_json(rule.model_dump_json(indent=2))


app.add_typer(rules_app, name="rules")


# ---------------------------------------------------------------------------
# Patterns Command Group
# ---------------------------------------------------------------------------
patterns_app = typer.Typer(name="patterns", help="Automated pattern discovery and threat catalog.")


@patterns_app.command("mine")
def patterns_mine(
    min_score: float = typer.Option(3.0, "--min-score", "-s", help="Minimum composite anomaly score (0-10)"),
    max_patterns: int = typer.Option(200, "--max-patterns", "-n", help="Maximum patterns to retain"),
) -> None:
    """Run unsupervised pattern miners across DuckDB events."""
    from app.pipeline.patterns.exporter import (
        export_iocs_csv,
        export_patterns_json,
        export_patterns_yaml,
    )
    from app.pipeline.patterns.runner import run_pattern_mining
    from app.pipeline.patterns.tune_report import generate_tuning_report
    from app.store import duck

    duck.init_db()
    console.print(f"[bold cyan]Running automated pattern discovery (min_score={min_score}, max={max_patterns})...[/bold cyan]")
    patterns, timings = run_pattern_mining(min_score=min_score, max_patterns=max_patterns)
    duck.save_patterns_batch(patterns)

    # Export default artifacts
    export_patterns_json(patterns)
    export_patterns_yaml(patterns)
    export_iocs_csv(patterns)
    generate_tuning_report()

    table = Table(title=f"Discovered Patterns ({len(patterns)} retained in {timings.get('total', 0):.2f}s)")
    table.add_column("Pattern ID", style="cyan")
    table.add_column("Kind", style="magenta")
    table.add_column("Score", justify="right")
    table.add_column("Support", justify="right")
    table.add_column("ATT&CK", style="yellow")
    table.add_column("Title")

    for p in patterns[:20]:
        tech_str = f"{p.suggested_technique or ''} ({p.suggested_tactic or ''})".strip()
        table.add_row(
            p.pattern_id,
            p.kind,
            f"{p.score:.1f}",
            str(p.support),
            tech_str,
            p.title[:60] + ("..." if len(p.title) > 60 else ""),
        )

    console.print(table)
    if len(patterns) > 20:
        console.print(f"... and {len(patterns) - 20} more patterns stored in DuckDB.")
    console.print("[green]Exported artifacts: data/patterns.json, data/patterns.yaml, data/iocs.csv, data/tune_report.json[/green]")


@patterns_app.command("list")
def patterns_list(
    status: str | None = typer.Option(None, "--status", help="Filter by status: new, approved, rejected"),
    kind: str | None = typer.Option(None, "--kind", help="Filter by miner kind"),
    limit: int = typer.Option(50, "--limit", "-l", help="Number of patterns to display"),
) -> None:
    """List discovered patterns from the catalog."""
    from app.store import duck

    duck.init_db()
    total, patterns = duck.list_patterns(status=status, kind=kind, limit=limit)

    table = Table(title=f"Pattern Catalog (Showing {len(patterns)} of {total} patterns)")
    table.add_column("Pattern ID", style="cyan")
    table.add_column("Kind", style="magenta")
    table.add_column("Status", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Support", justify="right")
    table.add_column("Title")

    for p in patterns:
        status_color = "green" if p["status"] == "approved" else ("red" if p["status"] == "rejected" else "blue")
        table.add_row(
            p["pattern_id"],
            p["kind"],
            f"[{status_color}]{p['status']}[/{status_color}]",
            f"{p['score']:.1f}",
            str(p["support"]),
            p["title"][:60],
        )

    console.print(table)


@patterns_app.command("approve")
def patterns_approve(pattern_id: str = typer.Argument(..., help="Pattern ID to approve")) -> None:
    """Approve a discovered pattern."""
    from app.store import duck

    duck.init_db()
    ok = duck.update_pattern_status(pattern_id, "approved")
    if ok:
        console.print(f"[green]SUCCESS:[/green] Pattern '{pattern_id}' approved.")
    else:
        console.print(f"[red]Error:[/red] Pattern '{pattern_id}' not found.")
        raise typer.Exit(code=1)


@patterns_app.command("reject")
def patterns_reject(pattern_id: str = typer.Argument(..., help="Pattern ID to reject")) -> None:
    """Reject a discovered pattern."""
    from app.store import duck

    duck.init_db()
    ok = duck.update_pattern_status(pattern_id, "rejected")
    if ok:
        console.print(f"[yellow]SUCCESS:[/yellow] Pattern '{pattern_id}' rejected.")
    else:
        console.print(f"[red]Error:[/red] Pattern '{pattern_id}' not found.")
        raise typer.Exit(code=1)


@patterns_app.command("export")
def patterns_export(
    format: str = typer.Option("json", "--format", "-f", help="Export format: json, yaml, csv"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Custom output path"),
) -> None:
    """Export patterns or IOCs to disk."""
    from app.pipeline.patterns.exporter import (
        export_iocs_csv,
        export_patterns_json,
        export_patterns_yaml,
    )
    from app.store import duck

    duck.init_db()
    fmt = format.lower().strip()
    if fmt == "json":
        path = str(output or Path("data/patterns.json"))
        export_patterns_json(output_path=path)
    elif fmt == "yaml":
        path = str(output or Path("data/patterns.yaml"))
        export_patterns_yaml(output_path=path)
    elif fmt in ("csv", "iocs"):
        path = str(output or Path("data/iocs.csv"))
        export_iocs_csv(output_path=path)
    else:
        console.print(f"[red]Unknown format '{format}'. Use json, yaml, or csv.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[green]Exported to {path}[/green]")


app.add_typer(patterns_app, name="patterns")


if __name__ == "__main__":
    app()

