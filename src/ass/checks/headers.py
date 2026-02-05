from __future__ import annotations

from typing import Dict, List

from ..models import Finding


def check_security_headers(headers: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []

    # Normalize header names to lowercase
    h = {k.lower(): v for k, v in headers.items()}

    def missing(
        fid: str,
        title: str,
        severity: str,
        remediation: str,
    ) -> None:
        findings.append(
            Finding(
                id=fid,
                title=title,
                severity=severity,
                description=f"The HTTP response is missing the {title}.",
                remediation=remediation,
            )
        )

    if "strict-transport-security" not in h:
        missing(
            "HDR-001",
            "HSTS header",
            "medium",
            "Enable HSTS on HTTPS responses (e.g., at load balancer or web server).",
        )

    if "content-security-policy" not in h:
        missing(
            "HDR-002",
            "Content-Security-Policy",
            "medium",
            "Add a Content-Security-Policy appropriate to your application to reduce XSS impact.",
        )

    if "x-frame-options" not in h:
        missing(
            "HDR-003",
            "X-Frame-Options",
            "low",
            "Set X-Frame-Options to DENY or SAMEORIGIN "
            "(or use CSP frame-ancestors).",
        )

    if "x-content-type-options" not in h:
        missing(
            "HDR-004",
            "X-Content-Type-Options",
            "low",
            "Set X-Content-Type-Options to 'nosniff'.",
        )

    if "referrer-policy" not in h:
        missing(
            "HDR-005",
            "Referrer-Policy",
            "low",
            "Set Referrer-Policy (e.g., no-referrer or "
            "strict-origin-when-cross-origin).",
        )

    return findings

