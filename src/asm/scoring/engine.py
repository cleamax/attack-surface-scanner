"""Deterministic risk scoring.

No weighting model, no machine learning: the bucket is decided by the most severe
finding present, so any score can be explained by pointing at one finding.
"""

from __future__ import annotations

from ..models import Asset, Risk

SEVERITY_WEIGHT: dict[str, int] = {"low": 1, "medium": 5, "high": 20}

#: How many findings are listed as the reason for an asset's score.
MAX_REASONS = 3


def score_asset(asset: Asset) -> tuple[Risk, list[str], int]:
    """Return ``(risk, reasons, score)`` for one asset.

    Risk is the severity of the worst finding: one high finding makes the asset high,
    regardless of how many low findings accompany it. The numeric score exists only to
    order assets within a bucket.
    """
    score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in asset.findings)
    severities = {f.severity for f in asset.findings}

    risk: Risk
    if "high" in severities:
        risk = "high"
    elif "medium" in severities:
        risk = "medium"
    else:
        risk = "low"

    ranked = sorted(
        asset.findings,
        key=lambda f: (SEVERITY_WEIGHT.get(f.severity, 0), f.id),
        reverse=True,
    )
    reasons = [f.title for f in ranked[:MAX_REASONS]]

    return risk, reasons, score


def summarize_scan(assets: list[Asset]) -> dict[str, int]:
    summary = {"low": 0, "medium": 0, "high": 0}
    for asset in assets:
        summary[asset.risk] = summary.get(asset.risk, 0) + 1
    return summary


def summarize_findings(assets: list[Asset]) -> dict[str, int]:
    summary = {"low": 0, "medium": 0, "high": 0}
    for asset in assets:
        for finding in asset.findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary
