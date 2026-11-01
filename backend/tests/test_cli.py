"""Tests for CaseFile CLI invocation, subcommands, and options."""

from __future__ import annotations

from app.cli import app
from app.config import settings
from app.store import duck
from typer.testing import CliRunner

runner = CliRunner()


def test_cli_help():
    """Verify casefile --help lists all primary commands."""
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "serve" in res.output
    assert "run" in res.output
    assert "ingest" in res.output
    assert "detect" in res.output
    assert "analyse" in res.output
    assert "stories" in res.output
    assert "incidents" in res.output
    assert "reach" in res.output
    assert "evaluate" in res.output
    assert "patterns" in res.output


def test_cli_package_entrypoint():
    """Verify importable casefile package entry point."""
    import casefile
    assert hasattr(casefile, "app")
    assert casefile.app == app


def test_cli_stories_empty_db(tmp_path, monkeypatch):
    """Verify casefile stories gracefully handles database with no incidents."""
    test_db = str(tmp_path / "test_cli_stories.duckdb")
    monkeypatch.setattr(settings, "duck_path", test_db)
    duck.close()
    duck.init_db()

    res = runner.invoke(app, ["stories"])
    assert res.exit_code == 0
    assert "No incidents found" in res.output
    duck.close()


def test_cli_detect_invocation(tmp_path, monkeypatch):
    """Verify casefile detect runs without error."""
    test_db = str(tmp_path / "test_cli_detect.duckdb")
    monkeypatch.setattr(settings, "duck_path", test_db)
    monkeypatch.setattr(
        "app.pipeline.detect.engine.run_detection",
        lambda rules, job_id, max_workers=2: {"total_detections": 0, "active_detections": 0},
    )
    duck.close()
    duck.init_db()

    res = runner.invoke(app, ["detect", "--workers", "1"])
    assert res.exit_code == 0
    assert "Running detection" in res.output
    duck.close()
