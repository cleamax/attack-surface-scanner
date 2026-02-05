# Attack Surface Scanner for SaaS Applications

A non-intrusive security scanner that inventories the public attack surface of a SaaS application and identifies common transport- and cloud-level misconfigurations.

This project is designed as a **practical security engineering signal** rather than a penetration testing tool.

---

## Overview

Modern SaaS applications often expose a large number of publicly reachable assets
(subdomains, APIs, dashboards, CDNs).
Misconfigurations at this layer are a frequent root cause of security incidents.

This scanner helps answer a simple but critical question:

> What is publicly exposed — and is it securely configured?

The tool focuses on **visibility, explainability, and safe-by-design checks**.

---

## What the scanner does (current state)

### Attack surface discovery
- Passive subdomain enumeration using Certificate Transparency logs
- Enterprise-safe fallback for restricted proxy environments
- Deterministic asset list (no active probing, no brute force)

### DNS resolution
- Resolves A and AAAA records for each discovered asset
- Identifies which assets are actually reachable
- Handles timeouts and NXDOMAIN safely

### HTTP / HTTPS probing
- Non-intrusive HTTP(S) requests only (GET)
- Redirect-aware endpoint discovery
- Proxy-aware execution for enterprise networks

### Security header analysis
Checks for common HTTP security headers:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

Each finding includes:
- Severity (low / medium)
- Short explanation
- Concrete remediation guidance

### Structured output
- Machine-readable JSON scan artifacts
- Deterministic scan metadata (scan ID, timestamps)
- Explicit warnings when external sources are unavailable

---

## What this tool intentionally does NOT do

- No exploitation
- No vulnerability scanning
- No authentication or crawling
- No port scanning
- No brute forcing

This is **not** a penetration testing tool.

The goal is **secure configuration visibility**, not exploitation.

---

## Safety & scope

- Uses only passive intelligence sources and standard HTTPS requests
- Safe to run in production-like environments
- Designed to degrade gracefully in restricted corporate proxy networks
- No credentials, secrets, or sensitive data are collected

---

## Example usage

python -m ass.cli example.com

Output:
- results/scan_<timestamp>.json
- Contains assets, endpoints, findings, and warnings

---

## Architecture (high level)

Input Domain  
→ Passive Enumeration (CT logs / fallback)  
→ DNS Resolution (A / AAAA)  
→ HTTP / HTTPS Probing  
→ Security Checks (Headers)  
→ Structured Scan Result (JSON)

The pipeline is deterministic and intentionally staged to allow
future extensions without refactoring the core design.

---

## Design decisions

- **Non-intrusive by design**  
  Avoids legal and operational risks associated with active scanning.

- **Enterprise-aware**  
  Explicit handling of authenticated proxies and restricted networks.

- **Explainability over volume**  
  Fewer findings, but each one is actionable and understandable.

- **Extensible architecture**  
  Clear separation between enumeration, probing, checks, and scoring.

---

## Roadmap / Planned extensions

### Phase 4 — TLS & certificate analysis
- Certificate expiration and issuer validation
- TLS protocol version detection (TLS 1.0–1.3)
- Identification of weak or deprecated configurations

### Phase 5 — Risk scoring
- Aggregated asset risk (low / medium / high)
- Deterministic scoring rules (no black-box ML)
- Clear reasoning behind each score

### Phase 6 — Cloud-native deployment
- Containerized execution
- Deployment on GCP Cloud Run or AWS ECS
- Centralized logging and artifact storage

### Phase 7 — Baseline comparison
- Detect newly exposed assets
- Highlight configuration drift over time
- Support continuous monitoring workflows

---

## Limitations

- Relies on external passive data sources for full coverage
- Does not detect application-layer vulnerabilities
- Results depend on publicly observable configuration only

These limitations are intentional.

---

## Status

Active development  
Current focus: transport security and configuration correctness

---

## License

MIT License