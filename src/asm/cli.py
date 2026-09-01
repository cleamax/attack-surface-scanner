from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import typer

from .pipeline import run_scan
from .reporting.console import render_console_summary

app = typer.Typer(
    help="Non-intrusive attack surface scanner for SaaS applications.",
    add_completion=False,
)


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
    out: Path = typer.Option(Path("results"), "--out", "-o", help="Output directory"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Per-request timeout in seconds"),
    summary: bool = typer.Option(True, "--summary/--no-summary", help="Print a console summary"),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="Exit non-zero if a finding of this severity or above is present: none, low, medium, high",
    ),
) -> None:
    """Scan a domain and write a JSON artifact.

    Only ever sends DNS lookups, standard GET requests and TLS handshakes. Scan only
    domains you are authorised to test.
    """
    levels = {"none": None, "low": "low", "medium": "medium", "high": "high"}
    if fail_on not in levels:
        raise typer.BadParameter(f"--fail-on must be one of: {', '.join(levels)}")

    out.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = out / f"scan_{timestamp}.json"

    result = run_scan(domain, timeout=timeout)
    out_file.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    if summary:
        render_console_summary(result, out_path=str(out_file))
    else:
        typer.echo(f"Results written to {out_file}")

    threshold = levels[fail_on]
    if threshold:
        order = ["low", "medium", "high"]
        wanted = order[order.index(threshold) :]
        hits = sum(result.finding_summary.get(level, 0) for level in wanted)
        if hits:
            typer.echo(f"\n{hits} finding(s) at severity '{threshold}' or above.", err=True)
            raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
