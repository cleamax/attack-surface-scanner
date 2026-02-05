from __future__ import annotations

from datetime import datetime
import uuid

import httpx

from .models import ScanResult, Asset, Endpoint
from .enum.crtsh import enumerate_subdomains
from .enum.resolver import resolve_ips
from .utils.http import probe_url
from .checks.headers import check_security_headers


def run_scan(domain: str) -> ScanResult:
    """
    Phase 3 pipeline:
    - Enumeration (with fallback)
    - DNS resolve
    - HTTP/HTTPS probe (non-intrusive)
    - Security header checks (only if reachable)
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

        # Probe HTTPS first, then HTTP
        for url in (f"https://{hostname}", f"http://{hostname}"):
            pr = probe_url(url)

            asset.endpoints.append(
                Endpoint(
                    url=url,
                    final_url=pr.final_url,
                    status_code=pr.status_code,
                    redirect_chain=pr.redirect_chain,
                )
            )

            if pr.error == "proxy_auth_required":
                if "Proxy auth required for HTTP probing. Run at home or set HTTPS_PROXY." not in scan.warnings:
                    scan.warnings.append("Proxy auth required for HTTP probing. Run at home or set HTTPS_PROXY.")
                continue

            # If successful response, fetch headers via httpx (reuse a single request)
            if pr.status_code:
                try:
                    with httpx.Client(
                        timeout=5.0,
                        follow_redirects=True,
                        max_redirects=5,
                        headers={"User-Agent": "ass-scanner/0.1"},
                        trust_env=True,
                    ) as client:
                        r = client.get(url)
                        asset.findings.extend(check_security_headers(dict(r.headers)))
                except httpx.ProxyError:
                    if "Proxy auth required for header checks. Run at home or set HTTPS_PROXY." not in scan.warnings:
                        scan.warnings.append("Proxy auth required for header checks. Run at home or set HTTPS_PROXY.")
                except Exception:
                    # ignore noisy edge cases for now
                    pass

                # If HTTPS worked, mark it
                if url.startswith("https://") and pr.status_code:
                    asset.uses_https = True
                    break  # don't bother with http if https works

        scan.assets.append(asset)

    scan.asset_count = len(scan.assets)
    scan.finished_at = datetime.utcnow()
    return scan
