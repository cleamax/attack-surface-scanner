from ass.models import Asset, Finding
from ass.scoring.engine import score_asset, summarize_scan


def test_score_asset_high_if_any_high_finding():
    a = Asset(
        hostname="a.example.com",
        findings=[
            Finding(
                id="X",
                title="Bad thing",
                severity="high",
                description="d",
                remediation="r",
            )
        ],
    )
    risk, reasons, score = score_asset(a)
    assert risk == "high"
    assert "Bad thing" in reasons
    assert score > 0


def test_score_asset_medium_if_any_medium_finding():
    a = Asset(
        hostname="b.example.com",
        findings=[
            Finding(
                id="Y",
                title="Medium thing",
                severity="medium",
                description="d",
                remediation="r",
            )
        ],
    )
    risk, reasons, _ = score_asset(a)
    assert risk == "medium"
    assert reasons[0] == "Medium thing"


def test_score_asset_low_if_no_findings():
    a = Asset(hostname="c.example.com", findings=[])
    risk, reasons, score = score_asset(a)
    assert risk == "low"
    assert reasons == []
    assert score == 0


def test_summarize_scan_counts_risks():
    a1 = Asset(hostname="a", risk="high")
    a2 = Asset(hostname="b", risk="medium")
    a3 = Asset(hostname="c", risk="low")
    summary = summarize_scan([a1, a2, a3])
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 1