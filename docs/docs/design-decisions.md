# Design Decisions — Attack Surface Scanner (ASS)

This document summarizes the main engineering choices and the rationale behind them.
It is written to support interview discussion.

---

## 1) Why “non-intrusive” by design?

### Decision
ASS performs **passive discovery** + **minimal HTTP/TLS metadata checks** (safe GET, header inspection, TLS handshake).
It does not perform exploitation, brute force, or port scanning.

### Rationale
- Production-safe and ethically clearer
- Represents common real-world security engineering workflows (asset inventory + configuration validation)
- Reduces legal/operational risk and avoids “pentest tool” framing

### Trade-off
Lower coverage vs active scanning, but higher safety and clearer scope.

---

## 2) Why Certificate Transparency (CT logs) for subdomain enumeration?

### Decision
Primary subdomain discovery uses CT log data (via crt.sh), with a deterministic fallback list.

### Rationale
- CT is a high-signal passive source: certificates often reflect real public hostnames
- Avoids brute force wordlists and aggressive traffic patterns
- Demonstrates awareness of “real” internet-facing asset discovery approaches

### Trade-off
CT is incomplete and can be rate-limited/blocked; hence fallback behavior is required.

---

## 3) Why deterministic fallback for enterprise proxy environments?

### Decision
If external enumeration is blocked (e.g., proxy auth required), the tool emits a warning and uses a small deterministic hostname set.

### Rationale
- Corporate networks frequently restrict outbound intel sources
- Silent failure (“0 subdomains”) looks broken and is misleading
- Warnings make constraints explicit and keep the tool usable for demos

### Trade-off
Fallback list may include non-existent hostnames. DNS resolution step filters reachability.

---

## 4) Why staged pipeline architecture?

### Decision
Pipeline is intentionally linear and modular:
1) Enumerate → 2) Resolve DNS → 3) Probe HTTP/S → 4) Checks → 5) Score → 6) Output

### Rationale
- Easy to reason about, test, and extend
- Each stage has clear inputs/outputs
- Supports partial failure and degraded operation

### Trade-off
Not as fast as heavily concurrent designs (intentionally kept simple/clear).

---

## 5) Why focus on TLS + headers?

### Decision
Checks center on transport security and header hardening:
- Deprecated TLS versions
- Certificate expiry
- HSTS/CSP/XFO/nosniff/Referrer-Policy

### Rationale
- High-impact, common real-world misconfigurations
- Easy to explain, easy to fix
- Suitable for “visibility & prioritization” tools

### Trade-off
Does not detect app-layer vulnerabilities (intentional non-goal).

---

## 6) Why explainable (non-ML) risk scoring?

### Decision
Risk scoring is deterministic (low/medium/high) and provides top reasons per asset.

### Rationale
- Auditability and reproducibility matter in security
- Interviewers can inspect reasoning
- Avoids “black box” claims and makes the tool more trustworthy

### Trade-off
Less adaptive than ML-based scoring; but clarity is the goal.

---

## 7) Why JSON artifacts + rich console output?

### Decision
Primary output is a structured JSON artifact, plus a human-friendly CLI summary.

### Rationale
- JSON enables downstream tooling (dashboards, SIEM pipelines, diffing baselines)
- Console summary supports fast triage and “demoable” output in interviews
- Separation of machine + human outputs is a common professional pattern

### Trade-off
Requires designing stable data models; mitigated via Pydantic models.

---

## 8) Why `src/` layout and Pydantic models?

### Decision
Use `src/` package layout and typed data models:
- Asset, Endpoint, Finding, ScanResult

### Rationale
- Avoids import pitfalls and supports packaging best practices
- Typed models give stable contracts between pipeline stages
- Easier testing and extension

### Trade-off
Slightly more boilerplate than a single script, but higher signal.

---

## 9) Why CI (ruff + pytest) and multi-version Python?

### Decision
GitHub Actions runs:
- `ruff check .`
- `pytest`
- Python 3.10 / 3.11 / 3.12 matrix

### Rationale
- Strong engineering signal for reliability and maintainability
- Prevents regressions and keeps the repo “review-ready”
- Mirrors professional team expectations

---

## 10) What would I do next (engineering-focused)?

- Baseline & drift detection (new assets, risk deltas)
- Extended TLS checks (cipher suites, curves) with careful non-intrusive approach
- Output schema versioning + artifact metadata (tool version, git commit)
- Containerized execution (read-only job) for reproducible runs
