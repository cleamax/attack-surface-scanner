"""CLI wiring: artifact written, exit codes, console rendering."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from asm import cli
from asm.models import Asset, Finding, ScanResult

runner = CliRunner()


def _result(findings: list[Finding] | None = None) -> ScanResult:
    asset = Asset(
        hostname="www.example.com",
        ip_addresses=["203.0.113.10"],
        reachable=True,
        uses_https=True,
        tls_versions=["TLSv1.2", "TLSv1.3"],
        findings=findings or [],
    )
    from asm.scoring.engine import score_asset, summarize_findings, summarize_scan

    asset.risk, asset.risk_reasons, asset.risk_score = score_asset(asset)
    return ScanResult(
        scan_id="test",
        target_domain="example.com",
        started_at=dt.datetime.now(dt.timezone.utc),
        finished_at=dt.datetime.now(dt.timezone.utc),
        duration_seconds=1.0,
        discovery_source="fallback",
        asset_count=1,
        resolved_count=1,
        assets=[asset],
        risk_summary=summarize_scan([asset]),
        finding_summary=summarize_findings([asset]),
    )


def _finding(severity: str) -> Finding:
    return Finding(
        id="HDR-002",
        title="Content-Security-Policy not set",
        severity=severity,
        description="d",
        remediation="r",
    )


def test_writes_a_json_artifact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result())

    result = runner.invoke(cli.app, ["example.com", "--out", str(tmp_path)])

    assert result.exit_code == 0
    artifacts = list(tmp_path.glob("scan_*.json"))
    assert len(artifacts) == 1

    payload = json.loads(artifacts[0].read_text())
    assert payload["target_domain"] == "example.com"
    assert payload["schema_version"] == "2"


def test_no_summary_suppresses_the_table(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result())

    result = runner.invoke(cli.app, ["example.com", "--out", str(tmp_path), "--no-summary"])

    assert result.exit_code == 0
    assert "Attack surface" not in result.output


def test_fail_on_exits_non_zero_when_threshold_met(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Makes the scanner usable as a CI gate."""
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result([_finding("medium")]))

    result = runner.invoke(
        cli.app, ["example.com", "--out", str(tmp_path), "--fail-on", "medium"]
    )

    assert result.exit_code == 1


def test_fail_on_ignores_findings_below_threshold(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result([_finding("low")]))

    result = runner.invoke(cli.app, ["example.com", "--out", str(tmp_path), "--fail-on", "high"])

    assert result.exit_code == 0


def test_default_never_fails_the_build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result([_finding("high")]))

    result = runner.invoke(cli.app, ["example.com", "--out", str(tmp_path)])

    assert result.exit_code == 0


def test_invalid_fail_on_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result())

    result = runner.invoke(
        cli.app, ["example.com", "--out", str(tmp_path), "--fail-on", "critical"]
    )

    assert result.exit_code != 0


def test_console_summary_renders_findings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result([_finding("high")]))

    result = runner.invoke(cli.app, ["example.com", "--out", str(tmp_path)])

    assert "example.com" in result.output
    assert "HIGH" in result.output


def test_console_summary_handles_a_clean_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "run_scan", lambda domain, timeout=5.0: _result())

    result = runner.invoke(cli.app, ["example.com", "--out", str(tmp_path)])

    assert "No findings" in result.output
