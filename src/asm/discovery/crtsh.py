"""Passive asset discovery via Certificate Transparency logs.

Scope containment is the security-critical property of this module. CT log data is
attacker-influenceable: anyone can obtain a certificate for a lookalike domain, and it
will appear in the logs. If a hostname from that data reaches the probing stage without
a strict scope check, the scanner sends traffic to a host the operator never authorised.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

UA = {"User-Agent": "asm-scanner/0.2 (+https://github.com/richter-max/attack-surface-scanner)"}


@dataclass
class DiscoveryResult:
    hostnames: set[str]
    source: str = "unknown"
    warning: str | None = None
    out_of_scope_rejected: int = 0
    rejected_examples: list[str] = field(default_factory=list)


def in_scope(hostname: str, domain: str) -> bool:
    """True only for the apex domain itself or a genuine subdomain of it.

    A plain suffix test is not sufficient, and preventing that mistake is why this
    function exists: ``"evilexample.com".endswith("example.com")`` is ``True``, so a
    suffix check would authorise probing an unrelated, attacker-registered domain.

        >>> in_scope("www.example.com", "example.com")
        True
        >>> in_scope("example.com", "example.com")
        True
        >>> in_scope("evilexample.com", "example.com")
        False
        >>> in_scope("example.com.attacker.net", "example.com")
        False
    """
    host = hostname.strip().lower().rstrip(".")
    base = domain.strip().lower().rstrip(".")
    if not host or not base:
        return False
    return host == base or host.endswith("." + base)


def normalize(hostname: str, domain: str) -> str | None:
    """Clean a CT log entry and return it only if it falls inside the target scope."""
    host = hostname.strip().lower().rstrip(".")

    while host.startswith("*.") or host.startswith("."):
        host = host[2:] if host.startswith("*.") else host[1:]

    if not host or " " in host or "." not in host:
        return None

    return host if in_scope(host, domain) else None


def _from_crtsh(domain: str, timeout: int = 15) -> DiscoveryResult:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=timeout, headers=UA)
        if response.status_code != 200:
            return DiscoveryResult(
                set(), source="crt.sh", warning=f"crt.sh returned HTTP {response.status_code}"
            )

        # crt.sh serves an HTML error page when rate limiting.
        content_type = (response.headers.get("content-type") or "").lower()
        if "json" not in content_type and not response.text.lstrip().startswith("["):
            return DiscoveryResult(
                set(),
                source="crt.sh",
                warning="crt.sh did not return JSON (possibly blocked or rate-limited)",
            )

        entries = response.json()
    except requests.exceptions.ProxyError:
        return DiscoveryResult(
            set(),
            source="crt.sh",
            warning="Proxy authentication required to reach crt.sh (HTTP 407).",
        )
    except requests.exceptions.RequestException as exc:
        return DiscoveryResult(
            set(),
            source="crt.sh",
            warning=f"Network error reaching crt.sh: {exc.__class__.__name__}",
        )
    except ValueError:
        return DiscoveryResult(
            set(), source="crt.sh", warning="crt.sh response could not be parsed as JSON"
        )

    found: set[str] = set()
    rejected: list[str] = []

    for entry in entries:
        name_value = entry.get("name_value")
        if not name_value:
            continue
        for raw in str(name_value).splitlines():
            normalized = normalize(raw, domain)
            if normalized:
                found.add(normalized)
                continue
            candidate = raw.strip().lower().rstrip(".")
            if candidate and "." in candidate:
                rejected.append(candidate.lstrip("*."))

    unique_rejected = sorted(set(rejected))
    return DiscoveryResult(
        found,
        source="crt.sh",
        warning=None if found else "crt.sh returned no in-scope hostnames",
        out_of_scope_rejected=len(unique_rejected),
        rejected_examples=unique_rejected[:5],
    )


def fallback_hostnames(domain: str) -> set[str]:
    """Deterministic offline fallback: the apex plus common SaaS hostnames.

    The apex is included deliberately. An earlier version generated only prefixed
    hostnames, so scanning ``example.com`` never actually checked ``example.com``.
    """
    prefixes = (
        "www",
        "api",
        "auth",
        "app",
        "dashboard",
        "admin",
        "static",
        "cdn",
        "assets",
        "status",
    )
    return {domain} | {f"{prefix}.{domain}" for prefix in prefixes}


def discover_hostnames(domain: str, timeout: int = 15) -> DiscoveryResult:
    """Passive discovery with graceful fallback. The apex is always included."""
    domain = domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return DiscoveryResult(set(), source="none", warning="Invalid or empty domain")

    result = _from_crtsh(domain, timeout=timeout)
    if result.hostnames:
        result.hostnames.add(domain)
        return result

    return DiscoveryResult(
        fallback_hostnames(domain),
        source="fallback",
        warning=(result.warning or "External discovery unavailable")
        + "; using the built-in hostname list. Coverage is not representative.",
        out_of_scope_rejected=result.out_of_scope_rejected,
        rejected_examples=result.rejected_examples,
    )
