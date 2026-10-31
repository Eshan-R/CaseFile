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

