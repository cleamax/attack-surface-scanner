from __future__ import annotations

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import Asset, ScanResult


def _top_assets(assets: List[Asset], limit: int = 10) -> List[Asset]:
    # Sort by risk (high > medium > low), then by number of findings
    order = {"high": 2, "medium": 1, "low": 0}
    return sorted(
        assets,
        key=lambda a: (order.get(a.risk, 0), len(a.findings)),
        reverse=True,
    )[:limit]


def render_console_summary(result: ScanResult, out_path: str | None = None) -> None:
    console = Console()

    title = f"Attack Surface Scan — {result.target_domain}"
    subtitle = f"Assets: {result.asset_count} | Risk: {result.risk_summary or {}}"
    if out_path:
        subtitle += f" | Output: {out_path}"

    console.print(Panel.fit(subtitle, title=title))

    # Warnings
    if result.warnings:
        warn_text = "\n".join(f"- {w}" for w in result.warnings)
        console.print(Panel(warn_text, title="Warnings", style="yellow"))

    # Risk summary table
    summary = result.risk_summary or {"low": 0, "medium": 0, "high": 0}
    t = Table(title="Risk Summary", show_lines=False)
    t.add_column("High", justify="right")
    t.add_column("Medium", justify="right")
    t.add_column("Low", justify="right")
    t.add_row(
        str(summary.get("high", 0)),
        str(summary.get("medium", 0)),
        str(summary.get("low", 0)),
    )
    console.print(t)

    # Top risky assets
    top = _top_assets(result.assets, limit=10)
    ta = Table(title="Top Risky Assets", show_lines=True)
    ta.add_column("Hostname", overflow="fold")
    ta.add_column("Risk", justify="center")
    ta.add_column("IPs", overflow="fold")
    ta.add_column("Findings", justify="right")
    ta.add_column("Top reasons", overflow="fold")

    for a in top:
        ips = ", ".join(a.ip_addresses[:4])
        if len(a.ip_addresses) > 4:
            ips += f" (+{len(a.ip_addresses) - 4})"
        reasons = "; ".join(a.risk_reasons[:3]) if a.risk_reasons else "-"
        ta.add_row(a.hostname, a.risk.upper(), ips or "-", str(len(a.findings)), reasons)

    console.print(ta)

    # Finding totals
    totals = {"high": 0, "medium": 0, "low": 0}
    for a in result.assets:
        for f in a.findings:
            totals[f.severity] = totals.get(f.severity, 0) + 1

    tf = Table(title="Finding Totals", show_lines=False)
    tf.add_column("High", justify="right")
    tf.add_column("Medium", justify="right")
    tf.add_column("Low", justify="right")
    tf.add_row(str(totals.get("high", 0)), str(totals.get("medium", 0)), str(totals.get("low", 0)))
    console.print(tf)