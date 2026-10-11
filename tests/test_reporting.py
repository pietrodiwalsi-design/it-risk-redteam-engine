import json
import os
import tempfile
import pytest

from src.reporting.report_generator import ReportGenerator


@pytest.fixture
def sample_audit_log():
    entries = [
        {
            "timestamp": "2026-10-11T15:00:00Z",
            "action": "SURFACE_SCAN",
            "prev_hash": "0" * 64,
            "entry_hash": "a" * 64,
            "data": {
                "host": "192.168.1.10",
                "status": "COMPLETED",
                "open_ports": [80, 443],
            },
        },
        {
            "timestamp": "2026-10-11T15:01:00Z",
            "action": "WEB_HEADERS_AUDIT",
            "prev_hash": "a" * 64,
            "entry_hash": "b" * 64,
            "data": {
                "url": "https://api.internal",
                "status": "COMPLETED",
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "title": "Missing HSTS Header",
                        "description": "Strict-Transport-Security missing",
                    }
                ],
            },
        },
        {
            "timestamp": "2026-10-11T15:02:00Z",
            "action": "LLM_EVALUATION",
            "prev_hash": "b" * 64,
            "entry_hash": "c" * 64,
            "data": {
                "endpoint": "https://ai.internal/v1/chat",
                "results": [
                    {
                        "vector_id": "LLM01-PI-DIRECT-01",
                        "category": "Direct Prompt Injection",
                        "owasp_id": "LLM01",
                        "vulnerability_detected": True,
                        "response_sample": "override acknowledged",
                    }
                ],
            },
        },
    ]

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.remove(temp_path)


def test_report_generator_cvss_and_summary(sample_audit_log):
    generator = ReportGenerator(sample_audit_log)
    exec_summary = generator.generate_executive_summary()

    assert "Executive Assessment Summary" in exec_summary
    assert "DORA" in exec_summary
    assert "TIBER-EU" in exec_summary
    assert "Critical" in exec_summary or "High" in exec_summary


def test_report_generator_technical_report(sample_audit_log):
    generator = ReportGenerator(sample_audit_log)
    tech_report = generator.generate_technical_report()

    assert "Technical Vulnerability & Remediation Report" in tech_report
    assert "Missing HSTS Header" in tech_report
    assert "LLM01-PI-DIRECT-01" in tech_report
    assert "VULNERABLE" in tech_report


def test_report_generator_write_reports(sample_audit_log):
    generator = ReportGenerator(sample_audit_log)
    with tempfile.TemporaryDirectory() as tmp_dir:
        paths = generator.write_reports(tmp_dir)
        assert os.path.exists(paths["executive_summary"])
        assert os.path.exists(paths["technical_report"])
        assert os.path.exists(paths["soc_deconfliction"])

        # Check that soc deconfliction is valid json
        with open(paths["soc_deconfliction"], "r") as f:
            data = json.load(f)
            assert len(data["events"]) == 3
