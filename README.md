# Attack Surface Scanner

[![CI](https://github.com/richter-max/attack-surface-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/richter-max/attack-surface-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![Type checked](https://img.shields.io/badge/mypy-strict-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A non-intrusive scanner that answers one question about a domain: **what is publicly
exposed, and which of it is configured badly?**

It discovers hostnames from Certificate Transparency logs, resolves them, probes HTTP and
HTTPS, and checks transport security and response headers. Output is a JSON artifact and
a console summary, with a deterministic risk score you can trace to a single finding.

## Scope and safety

The scanner sends DNS lookups, plain `GET` requests, and TLS handshakes. Nothing else:
no port scanning, no brute forcing, no authentication, no crawling, no exploitation.
It is safe to run against production, and it is not a penetration testing tool.

**Only scan domains you are authorised to test.**

That authorisation is enforced in code, not just documented. Certificate Transparency
data is attacker-influenceable — anyone can obtain a certificate for `evilyourcompany.com`
and it will appear in the logs under a naive search. Every discovered hostname is checked
against the target scope before it is probed, and hostnames outside it are counted and
reported rather than silently scanned:

```python
def in_scope(hostname: str, domain: str) -> bool:
    return host == base or host.endswith("." + base)
```

A suffix test would not be enough: `"evilexample.com".endswith("example.com")` is `True`.
This is the property `tests/test_scope.py` exists to defend.

## Install and run

```bash
pip install -e .

asm example.com
asm example.com --out reports --timeout 10
asm example.com --fail-on high        # exit 1 if a high finding is present
```

Output goes to `results/scan_<timestamp>.json` alongside a console summary:

```
╭──────────────── Attack surface — example.com ─────────────────╮
│ 34 hostnames, 21 resolved  |  discovery: crt.sh  |  46.2s     │
│ results/scan_20260901_101500.json                             │
╰───────────────────────────────────────────────────────────────╯
                Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━┓
┃                ┃ High ┃ Medium ┃ Low ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━┩
│ Assets by risk │    2 │      6 │  13 │
│ Findings       │    3 │     11 │  18 │
└────────────────┴──────┴────────┴─────┘
```

The `--fail-on` flag makes the scanner usable as a CI gate: run it against your own
domains on a schedule and fail the job when something regresses.

## What it checks

**Discovery** — passive enumeration from Certificate Transparency, scope-filtered, with a
deterministic fallback list when the source is unreachable. The apex domain is always
included.

**Reachability** — A and AAAA resolution, then HTTP and HTTPS probes with redirect
following.

**Transport** — supported TLS versions, certificate expiry, chain validity, hostname
match. Whether the host answers over plaintext at all, and whether HTTP redirects to
HTTPS.

**Response headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy.

Every finding carries a severity, an explanation of why it matters, remediation guidance,
and the response it was observed on.

### Findings

| ID | Severity | Condition |
| :--- | :--- | :--- |
| `NET-001` | high | Host answers over HTTP only |
| `NET-002` | medium | HTTP does not redirect to HTTPS |
| `TLS-001` | high | Certificate expired |
| `TLS-002` | medium | Certificate expires within 30 days |
| `TLS-003` | high | TLS 1.0 or 1.1 accepted |
| `TLS-004` | high | Neither TLS 1.2 nor 1.3 supported |
| `TLS-005` | high | Certificate not yet valid |
| `TLS-006` | high | Certificate hostname mismatch |
| `TLS-007` | medium | Certificate chain does not validate |
| `HDR-001` | medium | Strict-Transport-Security not set |
| `HDR-002` | medium | Content-Security-Policy not set |
| `HDR-003` | low | X-Frame-Options not set |
| `HDR-004` | low | X-Content-Type-Options not set |
| `HDR-005` | low | Referrer-Policy not set |

## Design decisions worth explaining

**Findings only come from application responses.** A 403 from a WAF, a 404, or a 502 from
a load balancer almost never carries security headers, while the application behind it
sets them correctly. Reporting those produces findings nobody can act on, so header
analysis is gated on 2xx and 3xx responses and records the status code as evidence.

**A header is judged against the scheme it was served over.** Browsers ignore
`Strict-Transport-Security` on plaintext HTTP, so its absence there is not the finding —
the finding is that the host answers over HTTP at all, which is `NET-001`.

**Risk is the worst finding, not a sum.** Fifty low-severity findings do not add up to a
high-risk asset. One expired certificate does. Any score can be explained by pointing at
a single finding, which is the whole point of not using a weighting model.

**Certificates are read as raw DER.** The obvious implementation — disable verification,
call `getpeercert()` — silently returns an empty dict, because CPython only decodes a
certificate it validated. This scanner attempts a verified handshake first and falls back
to parsing the DER, so expired and self-signed certificates are reported rather than
skipped. See below.

**Proxy failures are reported, not swallowed.** In a corporate network an authenticated
proxy will block outbound requests. The scanner detects HTTP 407 explicitly and emits a
warning saying the results are incomplete, rather than returning a clean-looking scan of
nothing.

More in [docs/design-decisions.md](docs/design-decisions.md) and
[docs/threat-model.md](docs/threat-model.md).

## Limitations

- **Coverage depends on Certificate Transparency.** Hosts that never had a public
  certificate will not be discovered. When crt.sh is unreachable the fallback list is
  used, and the scan says so — those results are not representative.
- **Configuration only.** No application-layer vulnerabilities, no authenticated
  surface, no business logic.
- **A missing header is not a vulnerability.** It is a missing mitigation. The severities
  here reflect that.
- **Cipher suites and curves are not analysed**, only protocol versions.
- **One observation, no history.** Drift detection is on the roadmap.

## Development

```bash
pip install -e ".[dev]"

pytest --cov=asm       # 120 tests
mypy                   # strict
ruff check .
```

CI runs the suite across Python 3.10, 3.11 and 3.12, and separately with sockets
disabled. That second job exists because a scanner's test suite must not depend on the
services it scans — an earlier version called crt.sh live from a unit test, so CI failed
whenever the service rate-limited.

### On the two bugs this version fixes

Both were in modules with no test coverage, and both failed silently.

**Certificate checks could never fire.** `get_certificate_info()` disabled verification so
that expired certificates could still be read, then called `getpeercert()`. CPython
returns `{}` from that call unless the peer certificate was validated, so `notAfter` was
never present and `TLS-001` and `TLS-002` were unreachable code. The scanner reported
clean certificates for everything, including expired ones.

**Discovery accepted hostnames outside the target scope.** `hostname.endswith(domain)`
authorised `evilexample.com` for the target `example.com`. Since CT data is
attacker-influenceable, that meant a third party could cause the scanner to send traffic
to a host the operator never authorised — the one category of bug a scanner really cannot
have.

`tests/test_scope.py` and `tests/test_tls.py` are the regression suites for these.

```text
src/asm/
├── checks/       # TLS and header analysis
├── discovery/    # CT enumeration with scope filtering, DNS resolution
├── reporting/    # console output
├── scoring/      # deterministic risk buckets
├── utils/        # HTTP probing
├── models.py     # pydantic schema for the JSON artifact
└── pipeline.py   # scan orchestration
```

## Roadmap

- Baseline comparison and drift detection between scans
- Cipher suite and curve analysis
- Additional discovery sources beyond Certificate Transparency
- Containerised read-only execution

## License

MIT

## Contact

**max.richter.dev@proton.me** · [richtermax.com](https://www.richtermax.com/) ·
[LinkedIn](https://www.linkedin.com/in/maximilian-richter-40697a298/)

> Only run this against infrastructure you own or have written permission to test.
