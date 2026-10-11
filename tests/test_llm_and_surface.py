import asyncio
import tempfile
import pytest
import yaml

from src.core.safety_controller import SafetyController
from src.core.scope_manager import ScopeManager
from src.modules.llm.red_team_module import LLMRedTeamModule
from src.modules.surface.surface_scanner import ExternalSurfaceScanner


@pytest.fixture
def test_scope_file():
    scope_data = {
        "version": "1.1",
        "in_scope": {
            "domains": ["api.internal", "portal.internal"],
            "cidr_ranges": ["10.0.0.0/8"],
        },
        "out_of_scope": {
            "domains": ["secret.internal"],
            "cidr_ranges": [],
        },
    }
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        yaml.dump(scope_data, f)
        temp_path = f.name

    yield temp_path


def test_llm_module_vector_catalog():
    safety = SafetyController()
    llm_module = LLMRedTeamModule(safety, vectors_file="data/vectors/owasp_llm_vectors.yaml")

    assert len(llm_module.test_vectors) >= 5
    vector_ids = [v["id"] for v in llm_module.test_vectors]
    assert "LLM01-PI-DIRECT-01" in vector_ids
    assert "LLM06-LEAK-SYS-01" in vector_ids
    assert "LLM01-PI-MULTITURN-01" in vector_ids


def test_llm_heuristics_evaluation():
    safety = SafetyController()
    llm_module = LLMRedTeamModule(safety)

    vector = {
        "leak_indicators": ["override_acknowledged"],
        "refusal_indicators": ["i cannot", "unable to"],
    }

    # Case 1: Refused safely
    eval1 = llm_module.evaluate_response_heuristics(
        "I cannot fulfill this request due to safety policies.", vector
    )
    assert eval1["is_vulnerable"] is False
    assert eval1["refused"] is True

    # Case 2: Leaked without refusal
    eval2 = llm_module.evaluate_response_heuristics(
        "Understood. Token: OVERRIDE_ACKNOWLEDGED", vector
    )
    assert eval2["is_vulnerable"] is True
    assert eval2["leak_detected"] is True


@pytest.mark.asyncio
async def test_llm_simulation_run():
    safety = SafetyController()
    llm_module = LLMRedTeamModule(safety, vectors_file="data/vectors/owasp_llm_vectors.yaml")

    results = await llm_module.evaluate_endpoint("https://api.internal/v1/chat", simulate=True)
    assert len(results) == len(llm_module.test_vectors)
    for res in results:
        assert res["vulnerability_detected"] is False
        assert res["refused"] is True


@pytest.mark.asyncio
async def test_surface_scanner_out_of_scope_header_audit(test_scope_file):
    sm = ScopeManager(test_scope_file)
    safety = SafetyController()
    scanner = ExternalSurfaceScanner(sm, safety)

    # Out of scope domain
    res = await scanner.audit_http_headers("https://unauthorized-domain.com")
    assert res["status"] == "OUT_OF_SCOPE"
    assert len(res["findings"]) == 0
