"""Tests for Typer CLI pattern commands."""

from __future__ import annotations

from app.cli import app
from app.config import settings
from app.pipeline.patterns.base import PatternCandidate
from app.store import duck
from typer.testing import CliRunner

runner = CliRunner()


def test_cli_patterns_mine_and_list(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_cli.duckdb")
    monkeypatch.setattr(settings, "duck_path", test_db)
    duck.close()
    duck.init_db()
    # Insert a sample pattern directly
    p = PatternCandidate(
        pattern_id="pat_cli_test_01",
        kind="burst",
        title="CLI Test Pattern",
        support=25,
        score=7.5,
    )
    duck.upsert_pattern(p)

    # 1. List
    result_list = runner.invoke(app, ["patterns", "list"])
    assert result_list.exit_code == 0
    assert "pat_cli_test_01" in result_list.output
    assert "CLI Test Pattern" in result_list.output

    # 2. Approve
    result_app = runner.invoke(app, ["patterns", "approve", "pat_cli_test_01"])
    assert result_app.exit_code == 0
    assert "approved" in result_app.output
    assert duck.get_pattern("pat_cli_test_01")["status"] == "approved"

    # 3. Reject
    result_rej = runner.invoke(app, ["patterns", "reject", "pat_cli_test_01"])
    assert result_rej.exit_code == 0
    assert "rejected" in result_rej.output
    assert duck.get_pattern("pat_cli_test_01")["status"] == "rejected"

    # 4. Export
    result_exp = runner.invoke(app, ["patterns", "export", "--format", "json"])
    assert result_exp.exit_code == 0
    assert "Exported to" in result_exp.output
    duck.close()
