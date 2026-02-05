from __future__ import annotations

from pathlib import Path
from datetime import datetime
import typer

from .pipeline import run_scan

app = typer.Typer(help="Attack Surface Scanner for SaaS applications")


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain (e.g., example.com)"),
    out: Path = typer.Option(Path("results"), help="Output directory"),
    format: str = typer.Option("json", help="Output format: json (more later)"),
):
    """
    Non-intrusive scan: models + pipeline skeleton (Phase 0).
    """
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = out / f"scan_{timestamp}.json"

    result = run_scan(domain)

    if format != "json":
        raise typer.BadParameter("Only 'json' is supported right now.")

    out_file.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Scan finished. Results written to {out_file}")


if __name__ == "__main__":
    app(prog_name="ass")