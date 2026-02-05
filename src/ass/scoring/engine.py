from __future__ import annotations

from typing import Dict, List, Tuple

from ..models import Asset

SEVERITY_WEIGHT = {
    "low": 1,
    "medium": 5,
    "high": 20,
}


def score_asset(asset: Asset) -> Tuple[str, List[str], int]:
    """
    Deterministic scoring:
    - Any HIGH finding => asset risk HIGH
    - Else >=2 MEDIUM => MEDIUM
    - Else 1 MEDIUM => MEDIUM
    - Else LOW

    Also returns:
    - top reasons (finding titles) to explain the score
    - numeric score for potential future sorting
    """
    score = 0
    high = 0
    medium = 0
    low = 0

    for f in asset.findings:
        w = SEVERITY_WEIGHT.get(f.severity, 0)
        score += w
        if f.severity == "high":
            high += 1
        elif f.severity == "medium":
            medium += 1
        else:
            low += 1

    # risk bucket
    if high >= 1:
        risk = "high"
    elif medium >= 1:
        risk = "medium"
    else:
        risk = "low"

    # reasons: pick most severe, then by weight
    sorted_findings = sorted(
        asset.findings,
        key=lambda f: SEVERITY_WEIGHT.get(f.severity, 0),
        reverse=True,
    )
    reasons = [f.title for f in sorted_findings[:3]]

    return risk, reasons, score


def summarize_scan(assets: List[Asset]) -> Dict[str, int]:
    summary = {"low": 0, "medium": 0, "high": 0}
    for a in assets:
        summary[a.risk] = summary.get(a.risk, 0) + 1
    return summary
