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
from .scoring.engine import score_asset, summarize_scan


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

    # --- Phase 1: Enumeration (with fallback + warning) ---
    enum_res = enumerate_subdomains(scan.target_domain)
    if enum_res.warning:
        scan.warnings.append(enum_res.warning)

    # --- Per asset ---
    for hostname in sorted(enum_res.subdomains):
        # --- Phase 2: DNS resolve ---
        ips = resolve_ips(hostname)
        asset = Asset(
            hostname=hostname,
            ip_addresses=ips,
            reachable=bool(ips),
        )

        # --- Phase 3/4: Probe + checks ---
        # Prefer HTTPS; fall back to HTTP if needed.
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

            # Proxy blocks in enterprise networks -> warn and skip external HTTP/TLS work
            if pr.error == "proxy_auth_required":
                if "Proxy auth required for HTTP/TLS checks. Run at home or set HTTPS_PROXY." not in scan.warnings:
                    scan.warnings.append(
                        "Proxy auth required for HTTP/TLS checks. Run at home or set HTTPS_PROXY."
                    )
                continue

            # Only do deeper checks if we got an HTTP response
            if not pr.status_code:
                continue

            # If HTTPS works, mark and run TLS + header checks, then stop trying HTTP
            if url.startswith("https://"):
                asset.uses_https = True

                # --- TLS analysis (Phase 4) ---
                supported = detect_supported_tls_versions(hostname)
                asset.findings.extend(analyze_tls_versions(supported))

                cert = get_certificate_info(hostname)
                if cert:
                    asset.findings.extend(analyze_certificate(cert))

                # --- Header checks (Phase 3) ---
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
                        scan.warnings.append(
                            "Proxy auth required for header checks. Run at home or set HTTPS_PROXY."
                        )
                except Exception:
                    # keep noise low for Phase 0–5; improve later with structured errors
                    pass

                break  # HTTPS successful -> do not probe HTTP

            # If only HTTP works, we can still do header checks on HTTP
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
                        asset.findings.extend(check_security_headers(dict(r.headers)))
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
