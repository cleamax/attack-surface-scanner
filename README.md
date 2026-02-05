# Attack Surface Scanner for SaaS Applications

[![CI](https://github.com/cleamax/attack-surface-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/cleamax/attack-surface-scanner/actions)

A **non-intrusive attack surface and configuration security scanner** for SaaS applications.

The project is designed as a **practical security engineering signal** for Cloud / AppSec / Detection roles and focuses on *real-world constraints*, *explainability*, and *production-grade engineering practices*.

---

## Overview

Modern SaaS applications expose a constantly changing public attack surface:
subdomains, APIs, dashboards, CDNs, and cloud frontends.

Security incidents are often caused not by advanced exploits, but by:
- forgotten assets
- weak transport security
- missing security headers
- configuration drift

This tool answers a simple but critical question:

> **What is publicly exposed — and how risky is it?**

---

## What the scanner does (current state)

### ✅ Attack surface discovery
- Passive subdomain enumeration via Certificate Transparency logs
- Enterprise-safe fallback for restricted proxy environments
- Deterministic, non-bruteforce asset discovery

### ✅ DNS resolution & reachability
- Resolves A / AAAA records
- Identifies which assets are actually reachable
- Safe timeout and error handling

### ✅ HTTP / HTTPS probing
- Non-intrusive GET requests only
- Redirect-aware endpoint discovery
- Explicit proxy-awareness for enterprise networks

### ✅ Transport security checks
- TLS protocol version detection (TLS 1.0–1.3)
- Detection of deprecated TLS versions
- TLS certificate expiration analysis

### ✅ HTTP security header analysis
Checks for common misconfigurations:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

Each finding includes:
- Severity (low / medium / high)
- Short explanation
- Concrete remediation guidance

### ✅ Deterministic risk scoring
- Asset-level risk classification (low / medium / high)
- Explainable scoring rules (no ML / black box)
- Scan-level risk summary

### ✅ Structured output
- Machine-readable JSON artifacts
- Console summary with prioritized assets
- Explicit warnings when external sources are unavailable

---

## What this tool intentionally does NOT do

- No exploitation
- No vulnerability scanning
- No authentication or crawling
- No port scanning
- No brute forcing

This is **not** a penetration testing tool.

The goal is **visibility and prioritization**, not exploitation.

---

## Safety & scope

- Uses only passive intelligence and standard HTTPS requests
- Safe to run against production-like environments
- Designed to degrade gracefully in restricted corporate networks
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
Passive Enumeration (CT logs / fallback)
   │
   ▼
DNS Resolution (A / AAAA)
   │
   ▼
HTTP / HTTPS Probing
   │
   ▼
Security Checks
   ├─ TLS Versions
   ├─ Certificate Expiry
   └─ HTTP Security Headers
   │
   ▼
Risk Scoring (Asset + Scan Level)
   │
   ▼
Structured Result (JSON + Console Summary)
```

The pipeline is deterministic and intentionally staged to allow
future extensions without refactoring core components.

---

## Engineering & quality signals

- Clean `src/`-layout Python package
- Deterministic data models (Pydantic)
- Explainable scoring logic
- Unit tests for core security logic
- Linting and CI via GitHub Actions
- Python 3.10–3.12 compatibility

---

## Testing & CI

This repository uses **GitHub Actions** to ensure code quality:

- Unit tests (`pytest`)
- Static analysis (`ruff`)
- Multi-version Python matrix (3.10 / 3.11 / 3.12)

CI runs automatically on every push and pull request.

---

## Limitations

- Relies on passive public data sources for full coverage
- Does not detect application-layer vulnerabilities
- Results reflect observable configuration only

These limitations are intentional and documented.

---

## Roadmap (non-product, engineering-focused)

- Baseline comparison (detect newly exposed assets)
- Extended TLS configuration analysis (ciphers, curves)
- JSON schema validation & versioning
- Cloud execution (containerized, read-only execution)
- Optional read-only web viewer for scan artifacts

---

## Status

Active development  
Current focus: security signal quality and explainability

---

## License

MIT License
