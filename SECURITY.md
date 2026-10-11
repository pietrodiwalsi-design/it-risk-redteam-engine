# Security Policy & Responsible Use Guidelines

## 1. Ethical Mandate & Scope Policy
The **IT Risk & Red Teaming Assessment Engine** is designed strictly for authorized, defensive cybersecurity assessments, regulatory compliance verification (DORA Articles 26/27, TIBER-EU), and internal IT risk audits.

- **Explicit Authorization Required:** Probing, network scanning, or LLM evaluation against targets without prior written authorization from the verified legal asset owner is strictly prohibited.
- **Scope Boundary Enforcement:** Users must always configure and validate target boundaries in `scope.yaml`. Disabling or bypassing the `ScopeManager` is a direct violation of the software's license terms.
- **Non-Destructive Testing:** This engine is engineered exclusively for non-destructive discovery and proof-of-concept verification. Denial of Service (DoS) and destructive exploitation modules are explicitly forbidden.

---

## 2. Reporting Vulnerabilities in this Tooling
If you discover a security vulnerability, flaw in scope verification, or logic bug within this engine, please report it responsibly:

- **Primary Contact:** Peter Van Walsem (`pietrodiwalsi-design`)
- **Reporting Channel:** Please open a confidential security advisory on GitHub or email: `moshe.van.walsem@gmail.com`
- **Response Timeline:** Acknowledgment within 48 hours, with security patches prioritized according to severity.

---

## 3. Rules of Engagement & Deconfliction
When conducting assessments in production-adjacent environments:
1. Always notify relevant stakeholders (CISO, SOC leads) and define operational test windows in `scope.yaml`.
2. Utilize the automated `soc_deconfliction.json` export to assist security operations in matching alerts to authorized assessment timestamps.
3. Ensure the **Emergency Kill Switch** is actively monitored and reachable at all times during active runs.
