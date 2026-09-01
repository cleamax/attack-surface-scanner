"""Risk scoring and scan-level aggregation."""

from __future__ import annotations

import pytest

from asm.models import Asset, Finding
from asm.scoring.engine import score_asset, summarize_findings, summarize_scan


def finding(severity: str, title: str = "Something", fid: str = "X-001") -> Finding:
    return Finding(id=fid, title=title, severity=severity, description="d", remediation="r")


class TestScoreAsset:
    def test_no_findings_is_low(self) -> None:
        risk, reasons, score = score_asset(Asset(hostname="a.example.com"))
        assert (risk, reasons, score) == ("low", [], 0)

    @pytest.mark.parametrize(
        ("severities", "expected"),
        [
            (["low"], "low"),
            (["low", "low", "low"], "low"),
            (["medium"], "medium"),
            (["low", "medium"], "medium"),
            (["high"], "high"),
            (["low", "low", "medium", "high"], "high"),
        ],
    )
    def test_risk_is_the_worst_severity_present(self, severities: list[str], expected: str) -> None:
        asset = Asset(hostname="a.example.com", findings=[finding(s) for s in severities])
        risk, _, _ = score_asset(asset)
        assert risk == expected

    def test_many_low_findings_never_reach_high(self) -> None:
        """Volume must not substitute for severity."""
        asset = Asset(hostname="a.example.com", findings=[finding("low") for _ in range(50)])
        risk, _, score = score_asset(asset)
        assert risk == "low"
        assert score == 50

    def test_reasons_are_ordered_by_severity(self) -> None:
        asset = Asset(
            hostname="a.example.com",
            findings=[
                finding("low", "Minor", "A-1"),
                finding("high", "Serious", "B-1"),
                finding("medium", "Moderate", "C-1"),
            ],
        )
        _, reasons, _ = score_asset(asset)
        assert reasons == ["Serious", "Moderate", "Minor"]

    def test_reasons_are_capped(self) -> None:
        asset = Asset(
            hostname="a.example.com",
            findings=[finding("medium", f"F{i}", f"X-{i}") for i in range(10)],
        )
        _, reasons, _ = score_asset(asset)
        assert len(reasons) == 3

    def test_scoring_is_deterministic(self) -> None:
        asset = Asset(
            hostname="a.example.com",
            findings=[finding("medium", "B", "B-1"), finding("medium", "A", "A-1")],
        )
        assert score_asset(asset) == score_asset(asset)


class TestSummaries:
    def test_risk_summary_counts_assets(self) -> None:
        assets = [
            Asset(hostname="a", risk="high"),
            Asset(hostname="b", risk="medium"),
            Asset(hostname="c", risk="low"),
            Asset(hostname="d", risk="low"),
        ]
        assert summarize_scan(assets) == {"high": 1, "medium": 1, "low": 2}

    def test_finding_summary_counts_findings_not_assets(self) -> None:
        assets = [
            Asset(hostname="a", findings=[finding("high"), finding("high"), finding("low")]),
            Asset(hostname="b", findings=[finding("medium")]),
        ]
        assert summarize_findings(assets) == {"high": 2, "medium": 1, "low": 1}

    def test_empty_scan_summarizes_to_zeros(self) -> None:
        assert summarize_scan([]) == {"high": 0, "medium": 0, "low": 0}
        assert summarize_findings([]) == {"high": 0, "medium": 0, "low": 0}
