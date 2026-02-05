# Attack Surface Scanner for SaaS Applications

[![CI](https://github.com/cleamax/attack-surface-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/cleamax/attack-surface-scanner/actions)

A **non-intrusive attack surface and transport security scanner** for SaaS applications.

This project is intentionally built as a **practical security engineering signal** for
Cloud Security, Application Security, and Detection-focused roles.
The emphasis is on **real-world constraints**, **explainability**, and **production-grade engineering practices** rather than exploit-based scanning.

---

## Overview

Modern SaaS applications expose a constantly changing public attack surface:
subdomains, APIs, dashboards, CDNs, and cloud-managed frontends.

Many real-world security incidents are not caused by advanced exploits, but by:
- forgotten or undocumented assets
- weak TLS or certificate configuration
- missing HTTP security headers
- configuration drift over time

This project answers a simple but critical question:

> **What is publicly exposed — and how risky is it?**

---

## What the scanner does

### Attack surface discovery
- Passive subdomain enumeration via Certificate Transparency logs
- Deterministic, non-bruteforce asset discovery
- Explicit fallback behavior for restricted enterprise proxy environments

### DNS resolution & reachability
- Resolves A / AAAA records
- Identifies which assets are actually reachable
- Safe timeout and error handling

### HTTP / HTTPS probing
- Non-intrusive GET requests only
- Redirect-aware endpoint discovery
- Explicit proxy-awareness for corporate networks

### Transport security checks
- TLS protocol version detection (TLS 1.0–1.3)
- Detection of deprecated TLS versions (1.0 / 1.1)
- TLS certificate expiration analysis

### HTTP security header analysis
Checks for common security-relevant headers:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

Each finding includes:
- Severity (low / medium / high)
- Short technical explanation
- Concrete remediation guidance

### Deterministic risk scoring
- Asset-level risk classification (low / medium / high)
- Explainable scoring rules (no ML / black-box logic)
- Scan-level risk summary with top contributing reasons

### Structured output
- Machine-readable JSON artifacts for further processing
- Rich CLI summary for fast triage
- Explicit warnings when external sources are unavailable

---

## What this tool intentionally does NOT do

- No exploitation
- No vulnerability scanning
- No authentication or crawling
- No port scanning
- No brute forcing
- No intrusive traffic generation

This is **not** a penetration testing tool.

The goal is **visibility and prioritization**, not exploitation.

---

## Safety & scope

- Uses only passive intelligence sources and standard HTTPS requests
- Safe to run against production-like environments
- Designed to degrade gracefully in restricted enterprise networks
- No credentials, secrets, or sensitive data are collected

---

## Example usage

```bash
python -m ass.cli example.com
```

### Output
- `results/scan_<timestamp>.json` (structured artifact)
- Rich console summary:
  - Risk overview
  - Top risky assets
  - Finding counts
  - Environment warnings (e.g., proxy limitations)

---

## Architecture (high level)

```
Input Domain
   │
   ▼
Passive Enumeration (CT logs + deterministic fallback)
   │
   ▼
DNS Resolution (A / AAAA)
   │
   ▼
HTTP / HTTPS Probing (redirect-aware)
   │
   ▼
Security Checks
   ├─ TLS protocol versions
   ├─ Certificate expiry
   └─ HTTP security headers
   │
   ▼
Deterministic Risk Scoring
   │
   ▼
Structured Result (JSON + CLI Summary)

```

The pipeline is deterministic and intentionally staged to allow
future extensions without refactoring core components.

---

## Engineering & quality signals

- Clean `src/`-layout Python package
- Strongly typed data models (Pydantic)
- Deterministic, explainable scoring logic
- Unit tests for core security logic
- Linting and CI enforced via GitHub Actions
- Python 3.10–3.12 compatibility

---

## Testing & CI

This repository uses **GitHub Actions** to ensure engineering quality:

- Unit tests via `pytest`
- Static analysis via `ruff`
- Multi-version Python test matrix (3.10 / 3.11 / 3.12)

All checks must pass before changes are merged.

---

## Enterprise & proxy awareness

In real-world corporate environments, access to external intelligence
sources is often restricted by authenticated proxies.

This tool:
- Detects proxy-related failures explicitly
- Emits structured warnings instead of failing silently
- Continues scanning with degraded capabilities where possible

This behavior is intentional and mirrors real production constraints.

---

## Limitations

- Relies on passive public data sources for full coverage
- Does not detect application-layer vulnerabilities
- Results reflect observable configuration only

These limitations are intentional and documented.

---

## Interview talking points

This project is designed to be discussed in interviews:

- Why non-intrusive scanning instead of exploitation?
- Why Certificate Transparency as a primary signal?
- Why deterministic scoring instead of ML-based risk?
- How would you extend this for production use?
- What security signals would you explicitly avoid automating?

---

## Roadmap (engineering-focused)

- Baseline comparison & drift detection
- Extended TLS analysis (cipher suites, curves)
- JSON schema versioning
- Containerized, read-only cloud execution
- Optional read-only web viewer for scan artifacts

---

## Status

Active development  
Current focus: **signal quality, explainability, and robustness**

---

## License

MIT License

## Contact

📧 **max.richter.dev@proton.me**  

<a href="https://www.linkedin.com/in/maximilian-richter-40697a298/">
  <img src="https://img.shields.io/badge/-LinkedIn-0072b1?&style=for-the-badge&logo=linkedin&logoColor=white" />
</a>

<a href="https://github.com/cleamax">
  <img src="https://img.shields.io/badge/-GitHub-181717?&style=for-the-badge&logo=github&logoColor=white" />
</a>

> All testing and experimentation is performed legally and only with explicit consent.
