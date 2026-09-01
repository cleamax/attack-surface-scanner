from __future__ import annotations

import dns.exception
import dns.resolver


def resolve_ips(hostname: str, timeout: float = 2.0) -> list[str]:
    """Resolve A and AAAA records. Standard DNS lookups only, no zone transfers.

    An unresolvable hostname is a normal outcome during discovery, not an error, so
    lookup failures return an empty list rather than raising.
    """
    ips: set[str] = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for record_type in ("A", "AAAA"):
        try:
            for rdata in resolver.resolve(hostname, record_type):
                ips.add(str(rdata))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue

    return sorted(ips)
