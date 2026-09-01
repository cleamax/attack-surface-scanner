"""Scan pipeline: discovery, resolution, probing, checks, scoring."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from .checks.headers import check_security_headers, check_transport
from .checks.tls import (
    analyze_certificate,
    analyze_tls_versions,
    detect_supported_tls_versions,
    get_certificate_info,
)
from .discovery.crtsh import discover_hostnames
from .discovery.resolver import resolve_ips
from .models import Asset, Endpoint, Finding, ScanResult
from .scoring.engine import score_asset, summarize_findings, summarize_scan
from .utils.http import HttpProbeResult, probe_url

PROXY_WARNING = (
    "A proxy required authentication (HTTP 407). HTTP and TLS checks were skipped for "
    "affected hosts; results are incomplete. Set HTTPS_PROXY or run from an unrestricted network."
)


def _endpoint(result: HttpProbeResult, scheme: Literal["http", "https"]) -> Endpoint:
    return Endpoint(
        url=result.url,
        scheme=scheme,
        final_url=result.final_url,
        status_code=result.status_code,
        redirect_chain=result.redirect_chain,
        response_ms=result.response_ms,
        error=result.error,
    )


def scan_asset(hostname: str, timeout: float = 5.0) -> tuple[Asset, str | None]:
    """Resolve, probe and check a single hostname.

    Returns the asset and an optional scan-level warning.
    """
    ips = resolve_ips(hostname, timeout=timeout)
    asset = Asset(hostname=hostname, ip_addresses=ips, reachable=bool(ips))
    warning: str | None = None

    https = probe_url(f"https://{hostname}", timeout=timeout)
    http = probe_url(f"http://{hostname}", timeout=timeout)

    asset.endpoints = [_endpoint(https, "https"), _endpoint(http, "http")]

    if "proxy_auth_required" in (https.error, http.error):
        warning = PROXY_WARNING

    asset.uses_https = https.ok
    asset.http_reachable = http.ok
    asset.redirects_to_https = http.ok and http.final_scheme == "https"

    findings: list[Finding] = []

    if https.ok:
        asset.tls_versions = detect_supported_tls_versions(hostname, timeout=3.0)
        findings.extend(analyze_tls_versions(asset.tls_versions))

        certificate = get_certificate_info(hostname, timeout=3.0)
        if certificate:
            asset.certificate_expires = certificate.not_after
            findings.extend(analyze_certificate(certificate))

        findings.extend(
            check_security_headers(https.headers, status_code=https.status_code, scheme="https")
        )
    elif http.ok:
        # No HTTPS: header analysis still applies, but HSTS does not.
        findings.extend(
            check_security_headers(http.headers, status_code=http.status_code, scheme="http")
        )

    findings.extend(
        check_transport(
            uses_https=asset.uses_https,
            http_reachable=asset.http_reachable,
            redirects_to_https=asset.redirects_to_https,
        )
    )

    asset.findings = findings
    asset.risk, asset.risk_reasons, asset.risk_score = score_asset(asset)
    return asset, warning


def run_scan(domain: str, timeout: float = 5.0) -> ScanResult:
    """Non-intrusive attack surface scan.

    1. Passive discovery via Certificate Transparency, with a deterministic fallback
    2. DNS resolution (A / AAAA)
    3. HTTP and HTTPS probing, redirect-aware
    4. TLS version, certificate and security header checks
    5. Deterministic risk scoring
    """
    started = datetime.now(timezone.utc)
    scan = ScanResult(
        scan_id=str(uuid.uuid4()),
        target_domain=domain.strip().lower().rstrip("."),
        started_at=started,
    )

    discovery = discover_hostnames(scan.target_domain)
    scan.discovery_source = discovery.source
    scan.out_of_scope_rejected = discovery.out_of_scope_rejected

    if discovery.warning:
        scan.warnings.append(discovery.warning)
    if discovery.out_of_scope_rejected:
        examples = ", ".join(discovery.rejected_examples)
        scan.warnings.append(
            f"{discovery.out_of_scope_rejected} hostname(s) from Certificate Transparency "
            f"were outside the target scope and were not probed (e.g. {examples})."
        )

    for hostname in sorted(discovery.hostnames):
        asset, warning = scan_asset(hostname, timeout=timeout)
        if warning and warning not in scan.warnings:
            scan.warnings.append(warning)
        scan.assets.append(asset)

    finished = datetime.now(timezone.utc)
    scan.asset_count = len(scan.assets)
    scan.resolved_count = sum(1 for a in scan.assets if a.reachable)
    scan.risk_summary = summarize_scan(scan.assets)
    scan.finding_summary = summarize_findings(scan.assets)
    scan.finished_at = finished
    scan.duration_seconds = round((finished - started).total_seconds(), 2)
    return scan
