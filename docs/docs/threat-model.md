# Threat Model — Attack Surface Scanner (ASS)

## Purpose

ASS is a **non-intrusive** scanner that helps answer:

> What public-facing assets exist for a given SaaS domain, and what transport/header misconfigurations create risk?

It is intentionally **not** a penetration testing tool and does not perform exploitation.

---

## Scope

### In scope
- Passive asset discovery (Certificate Transparency + deterministic fallback)
- DNS resolution (A/AAAA)
- HTTP/HTTPS probing (safe GET, redirect-aware)
- Transport security checks:
  - TLS protocol versions (e.g., deprecated TLS 1.0/1.1)
  - Certificate expiry
- HTTP security header checks:
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Deterministic, explainable risk scoring
- JSON artifacts + CLI summary

### Out of scope (explicit non-goals)
- Exploitation or proof-of-concepts
- Port scanning
- Brute forcing subdomains/paths
- Authenticated crawling
- Vulnerability scanning (SQLi/XSS fuzzing, etc.)
- Any form of persistent agent/monitoring on target systems

---

## Assets & Data

### Assets scanned
- Public hostnames derived from CT logs and/or fallback list
- Resolved IP addresses (A/AAAA)
- HTTP response metadata (status code, headers)
- TLS handshake metadata (supported TLS versions, certificate validity dates)

### Data stored
- Only scan output artifacts (JSON):
  - assets, endpoints, findings, risk summary, warnings
- No credentials or secrets are collected.
- No cookies/session tokens are required.

### Data not stored
- Response bodies are not required for the current checks.
- No authenticated content, no user PII intended.

---

## Actors

- **Operator (legitimate user):** runs scans on domains they own/are authorized to assess.
- **Target infrastructure:** public SaaS endpoints (LB/CDN/app frontends).
- **External intel provider:** crt.sh / CT log interface.
- **Network middleboxes:** enterprise proxy performing TLS interception/authentication.

---

## Trust Boundaries & Attack Surfaces (of the tool)

1. **Operator environment**
   - Local machine where the tool is executed.
2. **Network boundary**
   - Outbound HTTPS to external intel sources (crt.sh) and to target endpoints.
3. **Output boundary**
   - JSON files written to disk; these can leak sensitive hostnames if mishandled.

---

## Key Threats (STRIDE-style) and Mitigations

### Spoofing
**Threat:** DNS responses or TLS interception could misrepresent targets.  
**Mitigations:**
- Tool is non-auth; it treats outputs as observational signals.
- Proxy/TLS interception issues are surfaced as **warnings** rather than ignored.
- Deterministic fallback prevents silent “empty scans”.

### Tampering
**Threat:** Output JSON could be modified to mislead.  
**Mitigations:**
- JSON artifacts are treated as reports, not as authoritative truth.
- Optional future: add artifact signing/hash summary.

### Repudiation
**Threat:** Operator cannot prove how results were produced.  
**Mitigations:**
- Scan includes timestamps and consistent pipeline behavior.
- Optional future: include tool version, config, and environment in artifact metadata.

### Information Disclosure
**Threat:** JSON artifact can reveal sensitive internal hostnames found via CT logs.  
**Mitigations:**
- No secrets are collected.
- README/docs recommend scanning only authorized targets.
- Optional future: add `--redact` mode (hash hostnames or mask).

### Denial of Service
**Threat:** Excessive requests could burden targets or external intel sources.  
**Mitigations:**
- Non-intrusive requests only, timeouts, limited redirects.
- No brute force enumeration; passive discovery only.
- Optional future: concurrency/rate limiting controls.

### Elevation of Privilege
**Threat:** Tool used as a stepping stone for exploitation.  
**Mitigations:**
- Explicit non-goals, no exploit modules.
- Findings provide defensive remediation guidance only.

---

## Safety Principles

- **Least intrusion:** passive intel + minimal HTTP/TLS metadata checks.
- **Explainability:** deterministic logic with reasons per risk classification.
- **Graceful degradation:** restricted networks produce warnings + fallback behavior.
- **Authorization expectation:** intended for domains the operator owns/controls.

---

## Residual Risks / Known Limitations

- Passive intel is incomplete: some assets may not be visible in CT logs.
- Proxy environments may block intel sources and/or affect TLS observations.
- The tool observes configuration signals only (no app-layer vulnerability detection).

---

## Future Hardening (optional)

- Artifact metadata: tool version, git commit, runtime env
- `--rate-limit` and `--max-assets`
- `--redact` output mode
- Signed artifacts (hash + signature)
