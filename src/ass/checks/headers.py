from __future__ import annotations

from typing import Dict, List
from ..models import Finding


def check_security_headers(headers: Dict[str, str]) -> List[Finding]:
    """
    Basic HTTP response header checks.
    Input: dict with lowercase keys recommended.
    """
    h = {k.lower(): v for k, v in headers.items()}
    findings: List[Finding] = []

    def missing(fid: str, title: str, severity: str, remediation: str):
        findings.append(
            Finding(
                id=fid,
                title=title,
                severity=severity,  # low/medium/high
                description=f"{title} is not set.",
                remediation=remediation,
                evidence="Header not present",
            )
        )

    if "strict-transport-security" not in h:
        missing("HDR-001", "Missing HSTS header", "medium", "Enable HSTS on HTTPS responses (e.g., at LB/web server).")

    if "content-security-policy" not in h:
        missing("HDR-002", "Missing Content-Security-Policy", "medium", "Add a CSP appropriate to your app to reduce XSS impact.")

    if "x-frame-options" not in h:
        missing("HDR-003", "Missing X-Frame-Options", "low", "Set X-Frame-Options to DENY or SAMEORIGIN (or use CSP frame-ancestors).")

    if "x-content-type-options" not in h:
        missing("HDR-004", "Missing X-Content-Type-Options", "low", "Set X-Content-Type-Options: nosniff.")

    if "referrer-policy" not in h:
        missing("HDR-005", "Missing Referrer-Policy", "low", "Set Referrer-Policy (e.g., no-referrer or strict-origin-when-cross-origin).")

    return findings
