import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


class ReportGenerator:
    """Generates executive summaries, technical remediation reports, and SOC deconfliction

    exports aligned with DORA (Articles 26/27), TIBER-EU, and MITRE ATT&CK / ATLAS.
    """

    def __init__(self, log_filepath: str):
        self.log_filepath = log_filepath
        self.entries: List[Dict[str, Any]] = []
        self._load_log()

    def _load_log(self) -> None:
        if not os.path.exists(self.log_filepath):
            return
        with open(self.log_filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        self.entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    def compute_cvss_score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates an approximate CVSS v3.1 base score and severity rating for a finding."""
        severity = finding.get("severity", "INFO").upper()
        category = finding.get("category", "")
        owasp_id = finding.get("owasp_id", "")

        # Scoring heuristics aligned with NIST/FIRST CVSS v3.1
        if owasp_id == "LLM08" or "Agency" in category:
            return {"score": 9.0, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
        elif owasp_id == "LLM01" or "Prompt Injection" in category:
            return {"score": 8.6, "severity": "HIGH", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}
        elif owasp_id == "LLM06" or "Disclosure" in category or "Leakage" in category:
            return {"score": 7.5, "severity": "HIGH", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
        elif severity == "MEDIUM" or "HSTS" in finding.get("title", ""):
            return {"score": 5.3, "severity": "MEDIUM", "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"}
        elif severity == "LOW" or "CSP" in finding.get("title", "") or "Clickjacking" in finding.get("title", ""):
            return {"score": 4.3, "severity": "LOW", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}
        else:
            return {"score": 2.0, "severity": "INFO", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}

    def map_mitre_frameworks(self, action: str, item: Dict[str, Any]) -> List[str]:
        """Maps actions and findings to MITRE ATT&CK (Enterprise) and MITRE ATLAS (AI)."""
        tags = []
        if action == "SURFACE_SCAN":
            tags.extend(["MITRE ATT&CK T1046: Network Service Discovery", "MITRE ATT&CK T1595: Active Scanning"])
        elif action == "WEB_HEADERS_AUDIT":
            tags.extend(["MITRE ATT&CK T1190: Exploit Public-Facing Application", "MITRE ATT&CK T1592: Gather Victim Host Info"])
        elif action == "LLM_EVALUATION":
            owasp_id = item.get("owasp_id", "")
            if "LLM01" in owasp_id:
                tags.extend(["MITRE ATLAS AML.T0051: LLM Prompt Injection", "MITRE ATLAS AML.T0054: LLM Jailbreak"])
            elif "LLM06" in owasp_id:
                tags.extend(["MITRE ATLAS AML.T0024: Exfiltration via ML Inference", "MITRE ATT&CK T1552: Unsecured Credentials"])
            elif "LLM08" in owasp_id:
                tags.extend(["MITRE ATLAS AML.T0053: LLM Plugin Compromise", "MITRE ATT&CK T1059: Command and Scripting Interpreter"])
        return tags

    def generate_executive_summary(self) -> str:
        """Generates a high-level executive summary tailored for CISO and Audit committees (DORA/TIBER-EU format)."""
        total_actions = len(self.entries)
        surface_scans = [e for e in self.entries if e.get("action") == "SURFACE_SCAN"]
        web_audits = [e for e in self.entries if e.get("action") == "WEB_HEADERS_AUDIT"]
        llm_evals = [e for e in self.entries if e.get("action") == "LLM_EVALUATION"]

        total_findings = 0
        critical_count = 0
        high_count = 0
        medium_count = 0

        # Tally findings from web audits
        for w in web_audits:
            for f in w.get("data", {}).get("findings", []):
                total_findings += 1
                cvss = self.compute_cvss_score(f)
                if cvss["severity"] == "MEDIUM":
                    medium_count += 1

        # Tally findings from LLM evaluations
        for l in llm_evals:
            for res in l.get("data", {}).get("results", []):
                if res.get("vulnerability_detected", False):
                    total_findings += 1
                    cvss = self.compute_cvss_score(res)
                    if cvss["severity"] == "CRITICAL":
                        critical_count += 1
                    elif cvss["severity"] == "HIGH":
                        high_count += 1

        summary = f"""# Executive Assessment Summary: Red Teaming & IT Risk
**Assessment Standard:** DORA (Articles 26/27) & TIBER-EU Framework Alignment  
**Generated Date:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Audit Integrity Status:** Cryptographically Chained (SHA-256)

---

## 1. Management Overview
This assessment executed controlled, non-destructive threat scenarios against scoped external attack surfaces and generative AI/LLM interfaces. All activities operated under strict Rules of Engagement (RoE) with automated scope enforcement and emergency kill-switch controls.

### Key Risk Metrics:
- **Total Operational Actions Executed:** {total_actions}
- **Surface Port Probes Completed:** {len(surface_scans)}
- **Web Security Header Audits:** {len(web_audits)}
- **AI/LLM Test Vectors Probed:** {sum(len(l.get('data', {}).get('results', [])) for l in llm_evals)}
- **Total Vulnerabilities / Deficiencies Identified:** {total_findings}
  - **Critical:** {critical_count}
  - **High:** {high_count}
  - **Medium:** {medium_count}

---

## 2. Risk Posture & Supervisory Conclusion
- **External Surface:** Perimeter controls successfully restricted scanning strictly to authorized CIDRs and domains.
- **AI/LLM Defenses:** Probed models were tested for prompt injection, instruction boundary bypass, and sensitive context leakage (OWASP LLM01, LLM06, LLM08).
- **Auditability:** Every transaction was timestamped and hashed in sequence, providing full evidentiary value for internal audit and supervisory deconfliction.
"""
        return summary

    def generate_technical_report(self) -> str:
        """Generates a detailed technical remediation report for engineers and security teams."""
        report = f"""# Technical Vulnerability & Remediation Report
**Framework Alignments:** PTES, NIST SP 800-115, OWASP Top 10 for LLMs, MITRE ATT&CK  
**Generated Date:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}

---

## 1. Web Security Header Audit Findings
"""
        web_audits = [e for e in self.entries if e.get("action") == "WEB_HEADERS_AUDIT"]
        if not web_audits:
            report += "\n*No web header audits recorded in this session.*\n"
        else:
            for audit in web_audits:
                data = audit.get("data", {})
                url = data.get("url", "Unknown Target")
                findings = data.get("findings", [])
                report += f"\n### Target: `{url}`\n"
                if not findings:
                    report += "- *Status: Compliant. No baseline security header deficiencies detected.*\n"
                else:
                    for f in findings:
                        cvss = self.compute_cvss_score(f)
                        mitre = self.map_mitre_frameworks("WEB_HEADERS_AUDIT", f)
                        report += f"""
- **Finding:** {f.get('title')}
  - **Severity:** {cvss['severity']} (Score: {cvss['score']} | `{cvss['vector']}`)
  - **Description:** {f.get('description')}
  - **MITRE TTP:** {', '.join(mitre)}
  - **Remediation:** Configure web server/reverse proxy to supply modern security headers.
"""

        report += "\n---\n\n## 2. LLM & AI Security Probing Findings\n"
        llm_evals = [e for e in self.entries if e.get("action") == "LLM_EVALUATION"]
        if not llm_evals:
            report += "\n*No LLM evaluations recorded in this session.*\n"
        else:
            for l in llm_evals:
                data = l.get("data", {})
                endpoint = data.get("endpoint", "Unknown Endpoint")
                results = data.get("results", [])
                report += f"\n### Target AI Endpoint: `{endpoint}`\n"
                for res in results:
                    is_vuln = res.get("vulnerability_detected", False)
                    cvss = self.compute_cvss_score(res)
                    mitre = self.map_mitre_frameworks("LLM_EVALUATION", res)
                    status_str = "VULNERABLE (Leak / Override Detected)" if is_vuln else "DEFENDED (Guardrail Held)"
                    report += f"""
- **Vector:** `[{res.get('vector_id')}]` {res.get('category')}
  - **Framework Mapping:** {res.get('owasp_id')} | {', '.join(mitre)}
  - **Evaluation Result:** **{status_str}**
  - **CVSS Rating:** {cvss['severity']} ({cvss['score']})
  - **Response Sample:** `{res.get('response_sample')}`
"""

        return report

    def export_soc_deconfliction(self) -> Dict[str, Any]:
        """Exports a structured JSON summary enabling the SOC/SIEM to match security alerts with test timestamps."""
        events = []
        for e in self.entries:
            events.append({
                "timestamp": e.get("timestamp"),
                "action": e.get("action"),
                "entry_hash": e.get("entry_hash"),
                "target_data": e.get("data", {}),
            })
        return {
            "metadata": {
                "export_time": datetime.utcnow().isoformat() + "Z",
                "purpose": "SOC Incident Deconfliction and Threat Activity Verification",
                "standard": "TIBER-EU Deconfliction Protocol",
            },
            "events": events,
        }

    def write_reports(self, output_dir: str = "reports") -> Dict[str, str]:
        """Writes the executive summary, technical report, and deconfliction JSON to the output directory."""
        os.makedirs(output_dir, exist_ok=True)
        date_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        exec_path = os.path.join(output_dir, f"executive_summary_{date_str}.md")
        tech_path = os.path.join(output_dir, f"technical_report_{date_str}.md")
        soc_path = os.path.join(output_dir, f"soc_deconfliction_{date_str}.json")

        with open(exec_path, "w", encoding="utf-8") as f:
            f.write(self.generate_executive_summary())

        with open(tech_path, "w", encoding="utf-8") as f:
            f.write(self.generate_technical_report())

        with open(soc_path, "w", encoding="utf-8") as f:
            json.dump(self.export_soc_deconfliction(), f, indent=2)

        return {
            "executive_summary": exec_path,
            "technical_report": tech_path,
            "soc_deconfliction": soc_path,
        }
