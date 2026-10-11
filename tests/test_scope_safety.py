import asyncio
import os
import tempfile
import pytest
import yaml

from src.core.scope_manager import ScopeManager
from src.core.safety_controller import SafetyController
from src.core.audit_logger import AuditLogger


@pytest.fixture
def temp_scope_file():
    scope_data = {
        "version": "1.1",
        "in_scope": {
            "domains": ["authorized.internal", "api.authorized.internal"],
            "cidr_ranges": ["192.168.1.0/24", "10.0.0.0/8"],
        },
        "out_of_scope": {
            "domains": ["forbidden.authorized.internal"],
            "cidr_ranges": ["192.168.1.254/32"],
        },
    }
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
        yaml.dump(scope_data, f)
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.remove(temp_path)


def test_scope_manager_ips(temp_scope_file):
    sm = ScopeManager(temp_scope_file)

    # In scope IP
    allowed, _ = sm.is_in_scope("192.168.1.10", verify_dns=False)
    assert allowed is True

    # Out of scope specific IP
    allowed, _ = sm.is_in_scope("192.168.1.254", verify_dns=False)
    assert allowed is False

    # External IP not in CIDR
    allowed, _ = sm.is_in_scope("8.8.8.8", verify_dns=False)
    assert allowed is False


def test_scope_manager_domains(temp_scope_file):
    sm = ScopeManager(temp_scope_file)

    # In scope domain
    allowed, _ = sm.is_in_scope("api.authorized.internal", verify_dns=False)
    assert allowed is True

    # Subdomain of forbidden domain
    allowed, _ = sm.is_in_scope("forbidden.authorized.internal", verify_dns=False)
    assert allowed is False

    # Out of scope domain
    allowed, _ = sm.is_in_scope("unauthorized.com", verify_dns=False)
    assert allowed is False


@pytest.mark.asyncio
async def test_safety_controller_kill_switch():
    safety = SafetyController(max_rps=10.0)
    await safety.enforce_rate_limit()

    # Trigger emergency kill switch
    safety.trigger_kill_switch("Test Emergency Stop")

    with pytest.raises(InterruptedError) as exc_info:
        await safety.enforce_rate_limit()

    assert "Emergency Kill Switch" in str(exc_info.value)


@pytest.mark.asyncio
async def test_safety_controller_token_budget():
    safety = SafetyController(max_rps=10.0, token_budget=100)
    safety.record_tokens(50)
    assert safety.tokens_consumed == 50

    # Exceed budget
    with pytest.raises(InterruptedError):
        safety.record_tokens(60)

    assert safety.kill_switch_triggered is True


def test_audit_logger_hash_chain():
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
        temp_log = f.name

    try:
        logger = AuditLogger(temp_log)
        logger.log_action("TEST_EVENT_1", {"key": "val1"})
        logger.log_action("TEST_EVENT_2", {"key": "val2"})
        logger.log_action("TEST_EVENT_3", {"key": "val3"})

        assert logger.verify_integrity() is True

        # Tamper with file
        with open(temp_log, "r") as f:
            lines = f.readlines()

        tampered_line = lines[1].replace("val2", "tampered_val")
        lines[1] = tampered_line

        with open(temp_log, "w") as f:
            f.writelines(lines)

        verifier = AuditLogger(temp_log)
        assert verifier.verify_integrity() is False

    finally:
        if os.path.exists(temp_log):
            os.remove(temp_log)
