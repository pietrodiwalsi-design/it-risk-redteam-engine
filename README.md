# IT Risk & Red Teaming Assessment Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Framework Alignment](https://img.shields.io/badge/framework-PTES%20%7C%20TIBER--EU%20%7C%20DORA%20%7C%20OWASP-green.svg)](docs/spec/requirements.md)
[![License](https://img.shields.io/badge/license-Restricted%20Ethical%20Use-red.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-responsible%20disclosure-blue.svg)](SECURITY.md)

An enterprise-grade, risk-governed assessment framework designed to evaluate external attack surfaces (networks, web applications, APIs) and AI/LLM interfaces (prompt injection, context leakage, excessive agency).

Unlike typical offensive security scripts, this engine is built from the ground up around **strict operational governance, non-destructive testing, and supervisory compliance** (aligning with **DORA Articles 26/27**, **TIBER-EU**, **PTES**, and **OWASP LLM Top 10**).

---

## Key Capabilities & Safety Controls

1. **Dual-Check Scope Boundary Enforcement (`ScopeManager`):**
   - Target authorization verified against `scope.yaml` prior to any network or API call.
   - Dual-layer validation: checks target domain names AND performs active DNS resolution to ensure resolved IPs belong strictly to permitted CIDRs.
2. **Operational Safety & Throttling (`SafetyController`):**
   - Asynchronous token-bucket request throttling (`max_rps`).
   - Thread-safe **Emergency Kill Switch** for immediate task termination and SOC deconfliction.
   - LLM token and financial cost ceiling guardrails.
3. **Cryptographically Tamper-Evident Audit Logging (`AuditLogger`):**
   - Streaming JSONL logging with SHA-256 hash chaining (`prev_hash` validation).
   - High evidentiary value for audit, regulatory, and incident response teams.
4. **AI & LLM Security Probing (`LLMRedTeamModule`):**
   - Automated evaluation of prompt injections (OWASP LLM01, single- and multi-turn priming), context/prompt leakage (LLM06), and excessive agency (LLM08).
   - Integrated heuristic response judge separating refusals from actual leaks.
5. **Non-Destructive Surface Discovery & Web Audit (`ExternalSurfaceScanner`):**
   - Rate-controlled service probing (ports 22, 80, 443, etc.).
   - Web security headers audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, server leakage).
6. **Regulatory Reporting & SOC Deconfliction (`ReportGenerator`):**
   - Generates Executive Summaries (DORA / TIBER-EU format), Technical Remediation Reports (CVSS v3.1 & MITRE ATT&CK/ATLAS), and SOC deconfliction JSON exports.

---

## Documentation & Practitioner Guides

- **[Practical Practitioner Guide (English)](docs/guides/practical_use_cases_guide_en.md)**: Comprehensive manual for IT Risk leaders (DORA TLPT readiness, Vendor AI audits, step-by-step test cases, and stakeholder briefing strategies).
- **[Praktijkgids & Use-Cases (Nederlands)](docs/guides/practical_use_cases_guide.md)**: Volledige Nederlandstalige gids voor de dagelijkse IT Risk praktijk.
- **[Requirements Specification (FRs & NFRs)](docs/spec/requirements.md)**: Full breakdown of 15 Functional Requirements and 16 Non-Functional Requirements, mapped to PTES, TIBER-EU, DORA, and NIST SP 800-115.
- **[Architecture Blueprint](docs/architecture/blueprint.md)**: Software design patterns, component modularity, and security gates.
- **[Development & Implementation Roadmap](docs/roadmap/implementation_plan.md)**: Phased delivery schedule (Sprints 0 to 5).
- **[Security Policy & Responsible Disclosure](SECURITY.md)**: Operational rules of engagement and vulnerability reporting procedures.

---

## Quickstart & Installation

### Requirements
- Python 3.10+
- `pip` or `uv`

### Installation
```bash
git clone https://github.com/pietrodiwalsi-design/it-risk-redteam-engine.git
cd it-risk-redteam-engine
pip install -e .
```

### Running Tests
```bash
python3 -m pytest tests/ -v
```

### Executing a Full Assessment with Reporting
```bash
python3 -m src.orchestrator \
  --scope configs/scope.example.yaml \
  --host 192.168.1.50 \
  --web https://api.example.internal \
  --llm https://ai-agent.example.internal/v1/chat \
  --report-dir reports/
```

Generated reports will be output to `reports/`:
- `executive_summary_*.md` (Management risk overview)
- `technical_report_*.md` (Engineering remediation actions & CVSS ratings)
- `soc_deconfliction_*.json` (SOC correlation timestamps & entry hashes)

---

## Legal, Copyright & Restricted Ethical Use License

**Copyright (c) 2026 Peter Van Walsem (pietrodiwalsi-design). All Rights Reserved.**

This software is governed by the **[Restricted Ethical & Defensive Use License](LICENSE)**:
- **Authorized Testing Only:** Execution is strictly limited to authorized internal IT risk auditing, defensive security assessments, and regulatory compliance validation (DORA, TIBER-EU) on systems owned or contracted with prior written authorization.
- **Strict Prohibitions:** Unauthorized scanning, unconsented probing, Denial of Service (DoS), malicious intrusion, and commercial redistribution without written permission are strictly prohibited.
- **Disclaimer of Liability:** The author and copyright holder assume zero liability for misuse, damages, operational outages, or legal violations resulting from use of this software.
