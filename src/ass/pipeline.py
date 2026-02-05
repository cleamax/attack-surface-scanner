from __future__ import annotations

from datetime import datetime
import uuid

import httpx

from .models import ScanResult, Asset, Endpoint
from .enum.crtsh import enumerate_subdomains
from .enum.resolver import resolve_ips
from .utils.http import probe_url
from .checks.headers import check_security_headers
from .checks.tls import (
    detect_supported_tls_versions,
    get_certificate_info,
    analyze_certificate,
    analyze_tls_versions,
)


def run_scan(domain: str) -> ScanResult:
    """
    Phase 4 pipeline:
    - Enumeration (with fallback)
    - DNS resolve
    - HTTP/HTTPS probing
    - Security headers
    - TLS version & certificate analysis
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
                if "Proxy auth required for HTTPS/TLS checks." not in scan.warnings:
                    scan.warnings.append("Proxy auth required for HTTPS/TLS checks.")
                continue

            if pr.status_code and url.startswith("https://"):
                asset.uses_https = True

                # --- TLS checks ---
                supported = detect_supported_tls_versions(hostname)
                asset.findings.extend(analyze_tls_versions(supported))

                cert = get_certificate_info(hostname)
                if cert:
                    asset.findings.extend(analyze_certificate(cert))

                # --- Header checks ---
                try:
                    with httpx.Client(
                        timeout=5.0,
                        follow_redirects=True,
                        headers={"User-Agent": "ass-scanner/0.1"},
                        trust_env=True,
                    ) as client:
                        r = client.get(url)
                        asset.findings.extend(check_security_headers(dict(r.headers)))
                except Exception:
                    pass

                break  # HTTPS successful, skip HTTP

        scan.assets.append(asset)

    scan.asset_count = len(scan.assets)
    scan.finished_at = datetime.utcnow()
    return scan