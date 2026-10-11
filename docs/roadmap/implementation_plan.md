# Implementation & Development Roadmap: IT Risk & Red Teaming Engine

## Project Overview
This roadmap outlines the phased development and enterprise implementation plan for the custom IT Risk & Red Teaming Assessment Engine. Designed for compliance with **TIBER-EU**, **DORA Article 26/27**, **PTES**, and **OWASP LLM Top 10**.

---

## Phased Delivery Schedule

```
[Fase 0: Setup & Scaffold]
        │
        ▼
[Fase 1: Core Governance & Safety] (ScopeManager met DNS, SafetyController, Hash-chained Logger)
        │
        ▼
[Fase 2: LLM & AI Security Probing] (Prompt injection, leakage, multi-turn, token limits)
        │
        ▼
[Fase 3: External Surface Probing] (Rate-limited TCP & HTTP surface analysis)
        │
        ▼
[Fase 4: Reporting & Framework Mapping] (CVSS scoring, MITRE ATT&CK & ATLAS, DORA reports)
        │
        ▼
[Fase 5: Sandbox Testing & CI/CD] (Integration tests against mock targets, Docker deployment)
```

### Phase 0: Scaffold & Documentation (Current)
- Initialize GitHub repository: `pietrodiwalsi-design/it-risk-redteam-engine`
- Write core specifications: Requirements Specification (`requirements.md`), Architectural Blueprint (`blueprint.md`), and Scoping templates (`scope.yaml`).
- Setup Python project tooling, typing (`mypy`), linting (`ruff`), and testing (`pytest`).

### Phase 1: Core Governance & Hard Safety Gates
- **ScopeManager:**
  - Strict YAML parsing and validation.
  - Dual-verification: Domain/Regex matching + active DNS-to-IP resolution against permitted CIDR blocks.
  - Explicit out-of-scope drop checks.
- **SafetyController:**
  - Token-bucket asynchronous rate-limiter (`max_rps`).
  - Thread-safe Emergency Kill Switch with instantaneous task cancellation.
  - LLM token and financial cost ceiling monitor.
- **AuditLogger:**
  - Tamper-evident JSONL logging using SHA-256 hash chaining (`prev_hash` validation).
  - Sensitive data sanitization (stripping bearer tokens/API keys from logs).

### Phase 2: AI & LLM Interface Security Probing
- Implement `LLMRedTeamModule` targeting OWASP Top 10 for LLMs:
  - *LLM01:* Direct & Indirect Prompt Injection.
  - *LLM06:* Sensitive Information & System Prompt Disclosure.
  - *LLM08:* Excessive Agency & Function Calling Parameter Tampering.
- Multi-turn interaction harness to test conversational jailbreaks.
- Automated evaluation heurism (pattern matching and semantic validation).

### Phase 3: External Surface Discovery Module
- Adapter architecture for external surface mapping.
- Async TCP port scanning on standard ports (22, 80, 443, 8080, 8443) with strict throttling.
- HTTP security header profiler (HSTS, CSP, X-Frame-Options, CORS).
- TLS configuration and cipher suite assessment.

### Phase 4: Reporting, Analytics & Framework Mapping
- Automated tagging of all findings to **MITRE ATT&CK** and **MITRE ATLAS** techniques.
- Generation of two reporting tiers:
  1. Executive Summary: Risk ratings, CVSS v3.1/v4.0 scores, DORA compliance overview.
  2. Technical Remediation Report: Exact reproducible proof-of-concept steps and remediation guidance.
- SOC Deconfliction export tool (quick hash/timestamp query to match against SIEM alerts).

### Phase 5: CI/CD & Production Hardening
- Containerization with Docker for headless execution.
- Automated regression suite using simulated vulnerable mock endpoints.
- Integration with OpenClaw skills ecosystem for automated assessment scheduling.
