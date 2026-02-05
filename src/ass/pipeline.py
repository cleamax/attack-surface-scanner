from __future__ import annotations

import uuid
from datetime import datetime

import httpx

from .checks.headers import check_security_headers
from .checks.tls import (
    analyze_certificate,
    analyze_tls_versions,
    detect_supported_tls_versions,
    get_certificate_info,
)
from .enum.crtsh import enumerate_subdomains
from .enum.resolver import resolve_ips
from .models import Asset, Endpoint, ScanResult
from .scoring.engine import score_asset, summarize_scan
from .utils.http import probe_url


def run_scan(domain: str) -> ScanResult:
    """
    Phase 1–5 scan pipeline (non-intrusive, enterprise-aware):

    1) Passive subdomain enumeration (CT logs) with deterministic fallback
    2) DNS resolve (A/AAAA)
    3) HTTP/HTTPS probe (GET, redirect-aware, proxy-aware)
    4) Security checks:
       - HTTP security headers
       - TLS versions
       - Certificate expiry
    5) Deterministic risk scoring per asset + scan summary

    Output: ScanResult (JSON artifact)
    """
    scan = ScanResult(
        scan_id=str(uuid.uuid4()),
        target_domain=domain.strip().lower(),
        started_at=datetime.utcnow(),
    )

    # --- Phase 1: Enumeration ---
    enum_res = enumerate_subdomains(scan.target_domain)
    if enum_res.warning:
        scan.warnings.append(enum_res.warning)

    for hostname in sorted(enum_res.subdomains):
        # --- Phase 2: DNS resolve ---
        ips = resolve_ips(hostname)
        asset = Asset(
            hostname=hostname,
            ip_addresses=ips,
            reachable=bool(ips),
        )

        # Prefer HTTPS; fall back to HTTP
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

            # Proxy blocks in enterprise networks
            if pr.error == "proxy_auth_required":
                proxy_warn = (
                    "Proxy auth required for HTTP/TLS checks. "
                    "Run at home or set HTTPS_PROXY."
                )
                if proxy_warn not in scan.warnings:
                    scan.warnings.append(proxy_warn)
                continue

            if not pr.status_code:
                continue

            if url.startswith("https://"):
                asset.uses_https = True

                # --- TLS analysis ---
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
                        max_redirects=5,
                        headers={"User-Agent": "ass-scanner/0.1"},
                        trust_env=True,
                    ) as client:
                        r = client.get(url)
                        asset.findings.extend(
                            check_security_headers(dict(r.headers))
                        )
                except httpx.ProxyError:
                    hdr_warn = (
                        "Proxy auth required for header checks. "
                        "Run at home or set HTTPS_PROXY."
                    )
                    if hdr_warn not in scan.warnings:
                        scan.warnings.append(hdr_warn)
                except Exception:
                    pass

                break  # HTTPS successful

            # HTTP-only fallback
            if url.startswith("http://"):
                try:
                    with httpx.Client(
                        timeout=5.0,
                        follow_redirects=True,
                        max_redirects=5,
                        headers={"User-Agent": "ass-scanner/0.1"},
                        trust_env=True,
                    ) as client:
                        r = client.get(url)
                        asset.findings.extend(
                            check_security_headers(dict(r.headers))
                        )
                except Exception:
                    pass

        # --- Phase 5: Risk scoring ---
        risk, reasons, _score = score_asset(asset)
        asset.risk = risk
        asset.risk_reasons = reasons

        scan.assets.append(asset)

    scan.asset_count = len(scan.assets)
    scan.risk_summary = summarize_scan(scan.assets)
    scan.finished_at = datetime.utcnow()
    return scan
