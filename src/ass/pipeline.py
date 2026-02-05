from __future__ import annotations

from datetime import datetime
import uuid

from .models import ScanResult, Asset, Endpoint, Finding


def run_scan(domain: str) -> ScanResult:
    """
    Phase 0 pipeline: returns a deterministic, explainable ScanResult structure
    with dummy data. Real enumeration/checks come in Phase 1+.
    """
    scan = ScanResult(
        scan_id=str(uuid.uuid4()),
        target_domain=domain,
        started_at=datetime.utcnow(),
    )

    asset = Asset(
        hostname=f"www.{domain}",
        ip_addresses=["93.184.216.34"],  # dummy
        reachable=True,
        uses_https=True,
        endpoints=[
            Endpoint(
                url=f"https://www.{domain}",
                final_url=f"https://www.{domain}/",
                status_code=200,
                redirect_chain=[],
                response_ms=123,
            )
        ],
        findings=[
            Finding(
                id="HDR-001",
                title="Missing HSTS header",
                severity="medium",
                description="HTTP Strict Transport Security is not enabled.",
                remediation="Enable HSTS at the load balancer or web server.",
                evidence="Strict-Transport-Security header not present",
            )
        ],
    )

    scan.assets.append(asset)
    scan.asset_count = len(scan.assets)
    scan.finished_at = datetime.utcnow()
    return scan
