# Practical Practitioner Guide & Use-Case Manual: IT Risk, Red Teaming & AI Probing
**Target Audience:** Head of IT Risk Management, CISO, Security Officers & IT Risk Auditors  
**Environment:** Hetzner Cloud Linux VPS & OpenClaw Autonomous Engine  
**Frameworks:** DORA (Articles 26 & 27), TIBER-EU, NIST SP 800-115, OWASP Top 10 for LLMs, MITRE ATT&CK / ATLAS  

---

## 1. Executive Context: Why Use This Tooling in Daily IT Risk Practice?

In enterprise financial and insurance environments (such as Life & Pensions), the second line of defense (IT Risk) traditionally faces a fundamental challenge: **reliance on retrospective reports provided by first-line IT teams or annual third-party penetration testers.**

With this custom **IT Risk & Red Teaming Engine**, IT Risk shifts from passive review to **independent, automated, and continuous risk validation**. Rather than waiting for an annual €50,000 penetration test, organizations can continuously, safely, and non-destructively validate security controls in strict compliance with supervisory standards.

### Core Regulatory Drivers:
1. **DORA (Digital Operational Resilience Act - Articles 26 & 27):**  
   DORA mandates continuous evaluation of ICT risks and periodic *Threat-Led Penetration Testing* (TLPT) for financial entities. This engine automates pre-engagement scoping, controlled execution, and SOC deconfliction.
2. **TIBER-EU Framework:**  
   Enforces mandatory Rules of Engagement (RoE), strict scope boundaries, and an instant Emergency Stop (*Kill Switch*). These safeguards are hard-coded directly into the engine's core.
3. **Generative AI & LLM Governance (OWASP LLM Top 10 & EU AI Act):**  
   When internal business units or third-party vendors introduce AI assistants or agentic integrations, traditional perimeter controls fail. This engine automates adversarial boundary testing against *Prompt Injection* (LLM01), *Sensitive Context Disclosure* (LLM06), and *Excessive Agency* (LLM08).

---

## 2. Why the Hetzner + OpenClaw Combination Is So Powerful

* **EU Data Sovereignty & Regulatory Compliance:** The Hetzner Cloud host is located in Nuremberg (Germany / EU). All audit logs, prompts, and target telemetry remain strictly within EU jurisdiction and never leave the private host.
* **Zero Vendor Lock-in & No Expensive SaaS Overhead:** Commercial attack surface management and AI red teaming platforms cost tens of thousands of euros annually. This framework runs on a private cloud instance with full transparency and ownership.
* **Autonomous Scheduling via OpenClaw:** OpenClaw acts as an intelligent scheduler and monitor. Using automated routines outside business hours, the engine can execute non-destructive surface evaluations and deliver executive reports directly to management.
* **Hetzner AUP Compliance by Design:** The dual-check `ScopeManager` (incorporating active DNS verification) ensures the server can never inadvertently scan arbitrary third-party infrastructure, preventing abuse detection triggers.

---

## 3. Four Concrete Real-World Use Cases

### Use Case 1: DORA TLPT Pre-Assessment & Scope Hygiene
* **Scenario:** A formal TIBER-EU or DORA threat-led penetration test is scheduled with regulators or external auditors in 90 days.
* **Application:** Scoped external assets are audited for open ports and web header configurations (HSTS, CSP, X-Frame-Options, technology disclosure).
* **Value:** IT Risk identifies and remedies perimeter hygiene findings *before* external inspectors arrive, allowing the formal red team exercise to focus on sophisticated adversary scenarios.

### Use Case 2: Third-Party Vendor AI & LLM Gatekeeper Audit
* **Scenario:** A vendor delivers a customer service chatbot or automated claims-processing LLM agent.
* **Application:** Before authorizing production deployment, IT Risk runs `LLMRedTeamModule` against the candidate endpoint. The engine executes automated test vectors—including multi-turn conversational priming—to evaluate instruction boundary resilience.
* **Value:** Produces an independent IT risk verification report with CVSS ratings and factual evidence of guardrail robustness.

### Use Case 3: Tamper-Evident Audit Trails & SOC Incident Deconfliction
* **Scenario:** The Security Operations Center (SOC) flags scanner activity and opens a high-priority security investigation.
* **Application:** IT Risk immediately exports `soc_deconfliction.json`. Leveraging SHA-256 hash chaining, the SOC can correlate timestamps and hashes to verify that the traffic originated from an authorized assessment.
* **Value:** Eliminates panic and wasted incident response cycles; ensures 100% evidentiary defensibility for internal and external auditors.

### Use Case 4: Continuous Attack Surface Drift Detection
* **Scenario:** Engineering teams inadvertently expose staging APIs or forget to enable HTTP Strict Transport Security (HSTS).
* **Application:** Automated periodic scans flag discrepancies and report perimeter drift.
* **Value:** Early detection of misconfigurations without waiting for quarterly reviews.

---

## 4. Hands-on Test Cases: Demonstrating Engine Capabilities

### Test Case A: Scope Boundary & Kill-Switch Validation
Demonstrates that the engine strictly refuses unauthorized targets and enforces immediate stops.

```bash
cd /root/repos/it-risk-redteam-engine
python3 -m pytest tests/test_scope_safety.py -v
```
* **Observed Output:**
  1. IP `192.168.1.254` is blocked because it is explicitly listed in `out_of_scope`.
  2. External IP `8.8.8.8` is rejected because it falls outside authorized CIDR blocks.
  3. The Emergency Kill Switch halts all active asynchronous routines upon trigger.
  4. Any modification of historical audit log lines is instantly caught by the SHA-256 hash-chain verifier.

---

### Test Case B: Web Surface & Security Header Inspection
Executes non-destructive security header auditing against authorized web endpoints.

```bash
cd /root/repos/it-risk-redteam-engine

python3 -m src.orchestrator \
  --scope configs/scope.example.yaml \
  --web https://api.example.internal \
  --host 192.168.1.50
```
* **Observed Output:** Analyzes web security headers (HSTS, CSP, Clickjacking, MIME sniffing) and writes a cryptographically hashed event to `audit_log.jsonl`.

---

### Test Case C: OWASP LLM Guardrail Stress-Testing
Executes standardized benchmark vectors against an AI model interface.

```bash
cd /root/repos/it-risk-redteam-engine

python3 -m src.orchestrator \
  --scope configs/scope.example.yaml \
  --llm https://ai-agent.example.internal/v1/chat
```
* **Observed Output:** Executes OWASP LLM01, LLM06, and LLM08 test vectors, tracks token consumption against the budget, and classifies outputs as `DEFENDED` or `VULNERABLE`.

---

### Test Case D: Full Regulatory Report & SOC Deconfliction Generation
Generates management summaries, technical remediation guides, and SOC correlation exports in one execution:

```bash
cd /root/repos/it-risk-redteam-engine

python3 -m src.orchestrator \
  --scope configs/scope.example.yaml \
  --web https://api.example.internal \
  --llm https://ai-agent.example.internal/v1/chat \
  --report-dir reports/
```

Files produced in `reports/`:
1. `executive_summary_*.md`: DORA/TIBER-EU management summary with risk metrics.
2. `technical_report_*.md`: Detailed findings with CVSS v3.1 scores, MITRE ATT&CK & ATLAS mappings, and remediation steps.
3. `soc_deconfliction_*.json`: Machine-readable correlation file for SOC/SIEM matching.

---

## 5. Stakeholder Communication Strategy

When briefing the **CISO**, **Audit Committee**, or **Executive Board**:
1. **The Strategic Context:** *"Under DORA and emerging AI regulatory frameworks, IT Risk must verify technical resilience independently and continuously."*
2. **The Controlled Approach:** *"We have built a dedicated, non-destructive assessment engine aligned with TIBER-EU standards, enforcing strict scoping, rate limiting, and instant emergency stop mechanisms."*
3. **The Tangible Deliverable:** *"Every assessment produces automated management summaries, technical remediation blueprints, and cryptographically verified audit trails for supervisory compliance."*
