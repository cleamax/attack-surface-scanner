from __future__ import annotations

from datetime import datetime
import uuid

from .models import ScanResult, Asset
from .enum.crtsh import enumerate_subdomains
from .enum.resolver import resolve_ips


def run_scan(domain: str) -> ScanResult:
    """
    Phase 2 pipeline:
    - Passive subdomain enumeration (with enterprise fallback)
    - DNS resolve A/AAAA for each asset
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
        ips = resolve_ips(hostname)
        asset = Asset(hostname=hostname, ip_addresses=ips, reachable=bool(ips))
        scan.assets.append(asset)

    scan.asset_count = len(scan.assets)
    scan.finished_at = datetime.utcnow()
    return scan