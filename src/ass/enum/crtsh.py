from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Set

import requests

UA = {"User-Agent": "ass-scanner/0.1"}


@dataclass
class EnumResult:
    subdomains: Set[str]
    warning: Optional[str] = None


def _normalize(hostname: str, domain: str) -> Optional[str]:
    h = hostname.strip().lower()
    if not h:
        return None
    if h.startswith("*."):
        h = h[2:]
    if not h.endswith(domain):
        return None
    return h


def _from_crtsh(domain: str, timeout: int = 15) -> EnumResult:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout, headers=UA)
        if r.status_code != 200:
            return EnumResult(set(), warning=f"crt.sh returned HTTP {r.status_code}")

        # crt.sh can return HTML on rate-limit/block
        ct = (r.headers.get("content-type") or "").lower()
        if "json" not in ct and not r.text.lstrip().startswith("["):
            return EnumResult(
                set(),
                warning="crt.sh did not return JSON (possibly blocked/rate-limited)",
            )

        data = r.json()
    except requests.exceptions.ProxyError:
        return EnumResult(
            set(),
            warning="Proxy authentication required to reach crt.sh (HTTP 407).",
        )
    except requests.exceptions.RequestException as e:
        return EnumResult(set(), warning=f"Network error reaching crt.sh: {e.__class__.__name__}")
    except ValueError:
        return EnumResult(set(), warning="crt.sh response could not be parsed as JSON")

    out: Set[str] = set()
    for entry in data:
        name_value = entry.get("name_value")
        if not name_value:
            continue
        for raw in name_value.splitlines():
            h = _normalize(raw, domain)
            if h:
                out.add(h)

    return EnumResult(out, warning=None if out else "crt.sh returned no subdomains")


def fallback_subdomains(domain: str) -> Set[str]:
    """
    Deterministic offline fallback: common SaaS hostnames.
    Keeps the tool useful without external intel sources.
    """
    prefixes = [
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
    ]
    return {f"{p}.{domain}" for p in prefixes}


def enumerate_subdomains(domain: str, timeout: int = 15) -> EnumResult:
    """
    Passive enumeration with graceful fallback.
    In restricted enterprise networks, external sources may be unreachable.
    """
    domain = domain.strip().lower()
    if not domain:
        return EnumResult(set(), warning="Empty domain")

    res = _from_crtsh(domain, timeout=timeout)
    if res.subdomains:
        return res

    fb = fallback_subdomains(domain)
    warning = res.warning or "External enumeration unavailable; using fallback list."
    return EnumResult(fb, warning=warning)