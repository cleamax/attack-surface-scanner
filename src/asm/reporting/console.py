from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import Asset, ScanResult

RISK_ORDER = {"high": 2, "medium": 1, "low": 0}
RISK_STYLE = {"high": "bold red", "medium": "yellow", "low": "dim"}


def _ranked(assets: list[Asset], limit: int) -> list[Asset]:
    return sorted(
        assets,
        key=lambda a: (RISK_ORDER.get(a.risk, 0), a.risk_score, len(a.findings)),
        reverse=True,
    )[:limit]


def render_console_summary(result: ScanResult, out_path: str | None = None, limit: int = 15) -> None:
    console = Console()

    header = (
        f"{result.asset_count} hostnames, {result.resolved_count} resolved  |  "
        f"discovery: {result.discovery_source}  |  {result.duration_seconds or 0:.1f}s"
    )
    if out_path:
        header += f"\n{out_path}"
    console.print(Panel.fit(header, title=f"Attack surface — {result.target_domain}"))

    if result.warnings:
        console.print(
            Panel("\n".join(f"• {w}" for w in result.warnings), title="Warnings", style="yellow")
        )

    counts = Table(title="Summary", show_lines=False)
    counts.add_column("", style="bold")
    counts.add_column("High", justify="right", style="red")
    counts.add_column("Medium", justify="right", style="yellow")
    counts.add_column("Low", justify="right", style="dim")
    for label, data in (("Assets by risk", result.risk_summary), ("Findings", result.finding_summary)):
        counts.add_row(
            label,
            str(data.get("high", 0)),
            str(data.get("medium", 0)),
            str(data.get("low", 0)),
        )
    console.print(counts)

    scored = [a for a in result.assets if a.findings]
    if not scored:
        console.print("[dim]No findings. Every resolved host passed all checks.[/dim]")
        return

    table = Table(title=f"Assets with findings (top {min(limit, len(scored))})", show_lines=True)
    table.add_column("Hostname", overflow="fold")
    table.add_column("Risk", justify="center")
    table.add_column("IPs", overflow="fold")
    table.add_column("TLS", overflow="fold")
    table.add_column("#", justify="right")
    table.add_column("Top findings", overflow="fold")

    for asset in _ranked(scored, limit):
        ips = ", ".join(asset.ip_addresses[:2])
        if len(asset.ip_addresses) > 2:
            ips += f" +{len(asset.ip_addresses) - 2}"
        tls = ", ".join(v.replace("TLSv", "") for v in asset.tls_versions) or "-"
        style = RISK_STYLE.get(asset.risk, "")
        table.add_row(
            asset.hostname,
            f"[{style}]{asset.risk.upper()}[/{style}]" if style else asset.risk.upper(),
            ips or "-",
            tls,
            str(len(asset.findings)),
            "; ".join(asset.risk_reasons) or "-",
        )

    console.print(table)
