from __future__ import annotations

from typing import List, Set
import dns.resolver
import dns.exception


def resolve_ips(hostname: str, timeout: float = 2.0) -> List[str]:
    """
    Resolve A and AAAA records for a hostname.
    Returns unique IPs as strings. Safe: standard DNS lookups only.
    """
    ips: Set[str] = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, rtype)
            for rdata in answers:
                ips.add(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            continue
        except Exception:
            continue

    return sorted(ips)
