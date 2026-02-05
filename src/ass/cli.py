from __future__ import annotations

from pathlib import Path
from datetime import datetime
import typer

from .pipeline import run_scan
from .reporting.console import render_console_summary

app = typer.Typer(help="Attack Surface Scanner for SaaS applications")


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain (e.g., example.com)"),
    out: Path = typer.Option(Path("results"), help="Output directory"),
    format: str = typer.Option("json", help="Output format: json"),
    no_summary: bool = typer.Option(False, help="Disable console summary output"),
):
    """
    Non-intrusive scan producing a structured JSON artifact and a console summary.
    """
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = out / f"scan_{timestamp}.json"

    result = run_scan(domain)

    if format != "json":
        raise typer.BadParameter("Only 'json' is supported right now.")

    out_file.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    if not no_summary:
        render_console_summary(result, out_path=str(out_file))

    typer.echo(f"Scan finished. Results written to {out_file}")


# Keep single-command invocation (your current CLI behavior)
if __name__ == "__main__":
    app()