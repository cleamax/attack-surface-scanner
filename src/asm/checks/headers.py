"""HTTP security header analysis.

Two constraints shape this module.

Findings are only produced for responses that plausibly came from the application. A
403 from a WAF, a 404, or a 502 from a load balancer routinely lacks security headers
while the application behind it sets them correctly - reporting those as missing headers
produces findings the operator cannot act on.

And a header is judged against the scheme it was served over. ``Strict-Transport-Security``
on a plain HTTP response is ignored by browsers, so its absence there is not a finding
about the header; the finding is that the host answers over HTTP at all.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Finding, Severity

#: Status codes whose bodies and headers are treated as coming from the application.
ANALYSABLE_STATUS = range(200, 400)


@dataclass(frozen=True)
class HeaderRule:
    header: str
    finding_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    https_only: bool = False


RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        header="strict-transport-security",
        finding_id="HDR-001",
        title="Strict-Transport-Security not set",
        severity="medium",
        description=(
            "Without HSTS a browser will still attempt plaintext HTTP on the first visit "
            "and after a cleared cache, leaving room for downgrade attacks."
        ),
        remediation="Set Strict-Transport-Security on HTTPS responses, starting with a short max-age.",
        https_only=True,
    ),
    HeaderRule(
        header="content-security-policy",
        finding_id="HDR-002",
        title="Content-Security-Policy not set",
        severity="medium",
        description=(
            "No CSP means any successful script injection executes with the full "
            "privileges of the page."
        ),
        remediation="Add a Content-Security-Policy, starting in report-only mode.",
    ),
    HeaderRule(
        header="x-frame-options",
        finding_id="HDR-003",
        title="X-Frame-Options not set",
        severity="low",
        description="The page can be framed by other origins, which enables clickjacking.",
        remediation="Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    ),
    HeaderRule(
        header="x-content-type-options",
        finding_id="HDR-004",
        title="X-Content-Type-Options not set",
        severity="low",
        description="Browsers may MIME-sniff responses and execute content as an unintended type.",
        remediation="Set X-Content-Type-Options to nosniff.",
    ),
    HeaderRule(
        header="referrer-policy",
        finding_id="HDR-005",
        title="Referrer-Policy not set",
        severity="low",
        description="Full URLs, including any path-based identifiers, may leak to third parties.",
        remediation="Set Referrer-Policy, for example strict-origin-when-cross-origin.",
    ),
)


def check_security_headers(
    headers: dict[str, str],
    status_code: int | None = None,
    scheme: str = "https",
) -> list[Finding]:
    """Report missing security headers on an application response.

    Returns an empty list when ``status_code`` is outside 2xx/3xx, because error pages
    are not representative of the application's configuration.
    """
    if status_code is not None and status_code not in ANALYSABLE_STATUS:
        return []

    present = {key.lower() for key in headers}
    is_https = scheme.lower() == "https"
    evidence = f"HTTP {status_code} over {scheme.upper()}" if status_code else f"over {scheme.upper()}"

    findings: list[Finding] = []
    for rule in RULES:
        if rule.https_only and not is_https:
            continue
        if rule.header not in present:
            findings.append(
                Finding(
                    id=rule.finding_id,
                    title=rule.title,
                    severity=rule.severity,
                    description=rule.description,
                    remediation=rule.remediation,
                    evidence=evidence,
                )
            )

    return findings


def check_transport(uses_https: bool, http_reachable: bool, redirects_to_https: bool) -> list[Finding]:
    """Findings about the transport itself rather than about headers.

    An asset served only over plaintext is the single most consequential thing an
    attack surface scan can report, and it was previously tracked but never scored.
    """
    findings: list[Finding] = []

    if http_reachable and not uses_https:
        findings.append(
            Finding(
                id="NET-001",
                title="Host answers over HTTP only",
                severity="high",
                description=(
                    "The host responds on port 80 but not over HTTPS. All traffic, including "
                    "any credentials or session tokens, is transmitted in plaintext."
                ),
                remediation="Terminate TLS for this host and redirect HTTP to HTTPS.",
                evidence="HTTPS probe failed; HTTP probe succeeded",
            )
        )
    elif http_reachable and uses_https and not redirects_to_https:
        findings.append(
            Finding(
                id="NET-002",
                title="HTTP does not redirect to HTTPS",
                severity="medium",
                description=(
                    "The host serves content over plaintext HTTP instead of redirecting to "
                    "its HTTPS endpoint."
                ),
                remediation="Return a 301 to the HTTPS URL for all plaintext requests.",
                evidence="HTTP responded without redirecting to HTTPS",
            )
        )

    return findings
