from __future__ import annotations

from datetime import datetime
import uuid

from .models import ScanResult, Asset
from .enum.crtsh import enumerate_subdomains


def run_scan(domain: str) -> ScanResult:
    """
    Phase 1 pipeline:
    - Passive subdomain enumeration (crt.sh)
    - Graceful fallback for restricted proxy environments
    """
    scan = ScanResult(
        scan_id=str(uuid.uuid4()),
        target_domain=domain,
        started_at=datetime.utcnow(),
    )

    enum_res = enumerate_subdomains(domain)

    if enum_res.warning:
        scan.warnings.append(enum_res.warning)

    for hostname in sorted(enum_res.subdomains):
        scan.assets.append(Asset(hostname=hostname))

    scan.asset_count = len(scan.assets)
    scan.finished_at = datetime.utcnow()
    return scan