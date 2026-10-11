# IT Risk & Red Teaming Assessment Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Framework Alignment](https://img.shields.io/badge/framework-PTES%20%7C%20TIBER--EU%20%7C%20DORA%20%7C%20OWASP-green.svg)](docs/spec/requirements.md)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

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

- **[Praktijkgids & Use-Cases (Dutch Guide)](docs/guides/practical_use_cases_guide.md)**: Volledige gids voor de dagelijkse IT Risk praktijk (DORA TLPT, Vendor AI audits, hands-on testcases en presentatietips voor CISO/Directie).
- **[Requirements Specification (FRs & NFRs)](docs/spec/requirements.md)**: Full breakdown of 15 Functional Requirements and 16 Non-Functional Requirements, mapped to PTES, TIBER-EU, DORA, and NIST SP 800-115.
- **[Architecture Blueprint](docs/architecture/blueprint.md)**: Software design patterns, component modularity, and security gates.
- **[Development & Implementation Roadmap](docs/roadmap/implementation_plan.md)**: Phased delivery schedule (Sprints 0 to 5).

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

## Governance & Compliance

Designed to support:
- **DORA (Digital Operational Resilience Act):** Articles 26 & 27 (Threat-Led Penetration Testing).
- **TIBER-EU:** Rules of Engagement, deconfliction protocols, and threat scenario emulation.
- **PTES & NIST SP 800-115:** Standardized technical testing lifecycle.
- **OWASP Top 10 for LLMs v1.1:** Verification of generative AI boundaries.
- **MITRE ATT&CK & MITRE ATLAS:** Adversarial threat mapping for traditional and AI assets.
