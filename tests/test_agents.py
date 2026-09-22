"""
Tests for the agent system (state, Red Agent parsing, Blue Agent checks).

Uses mocks for LLM calls — no actual API calls needed.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from vulnguard.agents.state import VulnGuardState, initial_state
from vulnguard.agents.red_agent import (
    RedAgentReport,
    _call_llm,
    red_agent_node,
    _validate_exploit_language,
    _sanitize_exploit,
)
from vulnguard.agents.blue_agent import _check_ast_loc_delta
from vulnguard.agents.judge_agent import JudgeVerdict, _truncate_error_logs, _validate, judge_agent_node


class TestInitialState:
    def test_creates_valid_state(self):
        state = initial_state(
            function_id="test_fn",
            code="int f() { return 1; }",
            language="c",
            risk_score=75.0,
            context_bundle={"imports": []},
        )
        assert state["function_id"] == "test_fn"
        assert state["attempt_number"] == 0
        assert state["max_attempts"] == 3
        assert state["pipeline_status"] == "TRIAGE"
        assert state["vulnerability_found"] is False

    def test_attempt_history_starts_empty(self):
        state = initial_state("fn", "code", "c", 50.0, {})
        assert state["attempt_history"] == []


class TestRedAgentReport:
    def test_no_vulnerability_report(self):
        report = RedAgentReport(vulnerability_found=False)
        assert not report.vulnerability_found
        assert report.vulnerability_type is None
        assert report.exploit_code_harness is None

    def test_full_report(self):
        report = RedAgentReport(
            vulnerability_found=True,
            vulnerability_type="SQL_INJECTION",
            cwe_id="CWE-89",
            severity="CRITICAL",
            affected_lines=[42, 43],
            explanation="User input concatenated into SQL query",
            exploit_type="python_script",
            exploit_code_harness='import requests\nr = requests.get("...',
            expected_stdout_regex="SQL Error",
            confidence=0.95,
        )
        assert report.vulnerability_found
        assert report.severity == "CRITICAL"

    def test_json_roundtrip(self):
        report = RedAgentReport(vulnerability_found=True, vulnerability_type="XSS")
        json_str = report.model_dump_json()
        parsed = RedAgentReport.model_validate_json(json_str)
        assert parsed.vulnerability_type == "XSS"

    def test_mock_response_matches_schema(self):
        with patch("vulnguard.agents.red_agent.cfg") as mock_cfg:
            mock_cfg.llm.mock_mode = True
            response = _call_llm([], risk_score=100.0)

        report = RedAgentReport.model_validate_json(response)
        assert report.vulnerability_found is True
        assert report.exploit_code_harness

    def test_schema_wrapped_response_is_unwrapped(self):
        state = initial_state("fn", "def fn():\n    pass", "python", 90.0, {})
        response = json.dumps(
            {
                "description": "Structured threat report",
                "properties": {"vulnerability_found": False},
            }
        )

        with patch("vulnguard.agents.red_agent._call_llm", return_value=response):
            result = red_agent_node(state)

        assert result["pipeline_status"] == "RED_COMPLETE"
        assert result["vulnerability_found"] is False


class TestExploitLanguageValidation:
    """Test EC-7.2: Language match validation."""

    def test_c_exploit_matches_c(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='#include <stdio.h>\nint main() { printf("pwned"); }',
        )
        assert _validate_exploit_language(report, "c") is True

    def test_python_exploit_mismatches_c(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='import os\nos.system("echo pwned")',
        )
        assert _validate_exploit_language(report, "c") is False

    def test_no_exploit_always_valid(self):
        report = RedAgentReport(vulnerability_found=True, exploit_code_harness=None)
        assert _validate_exploit_language(report, "c") is True


class TestExploitSanitization:
    """Test Section 4.3: Dangerous payload detection."""

    def test_removes_rm_rf(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='system("rm -rf /");',
            confidence=0.9,
        )
        sanitized = _sanitize_exploit(report)
        assert "DANGEROUS PAYLOAD REMOVED" in sanitized.exploit_code_harness
        assert sanitized.confidence == 0.0

    def test_preserves_safe_exploit(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='printf("test output");',
            confidence=0.9,
        )
        sanitized = _sanitize_exploit(report)
        assert "printf" in sanitized.exploit_code_harness
        assert sanitized.confidence == 0.9


class TestAntiTrivialityCheck:
    """Test Section 4.4: Destructive patch rejection."""

    def test_rejects_destructive_patch(self):
        original = "\n".join(["line"] * 100)
        patched = "\n".join(["line"] * 20)  # 80% reduction
        ok, reason = _check_ast_loc_delta(original, patched, min_ratio=0.4)
        assert ok is False
        assert "DESTRUCTIVE_PATCH" in reason

    def test_accepts_reasonable_patch(self):
        original = "\n".join(["line"] * 100)
        patched = "\n".join(["line"] * 80)  # 20% reduction
        ok, reason = _check_ast_loc_delta(original, patched, min_ratio=0.4)
        assert ok is True

    def test_accepts_equal_length(self):
        code = "int f() { return 1; }"
        ok, _ = _check_ast_loc_delta(code, code, min_ratio=0.4)
        assert ok is True

    def test_handles_empty_original(self):
        ok, _ = _check_ast_loc_delta("", "int f() { return 1; }", min_ratio=0.4)
        assert ok is True


class TestErrorLogTruncation:
    """Test Section 4.6: Error log filtering."""

    def test_short_logs_unchanged(self):
        logs = "error: undefined reference to 'foo'"
        result = _truncate_error_logs(logs, max_chars=2000)
        assert result == logs

    def test_long_logs_filtered(self):
        lines = ["noise line"] * 500 + ["error: something failed"] + ["more noise"] * 500
        logs = "\n".join(lines)
        result = _truncate_error_logs(logs, max_chars=500)
        assert "error: something failed" in result
        assert len(result) <= 600  # Some tolerance for truncation marker


class TestJudgeVerdict:
    def test_all_verdicts_are_strings(self):
        for v in JudgeVerdict:
            assert isinstance(v.value, str)

    def test_pass_is_pass(self):
        assert JudgeVerdict.PASS.value == "PASS"

    def test_missing_docker_returns_static_only_verdict(self):
        state = initial_state("fn", "def fn():\n    return 1", "python", 90.0, {})
        state["patched_code"] = "def fn():\n    return 2"

        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available",
            return_value=False,
        ):
            verdict, message = _validate(state)

        assert verdict == JudgeVerdict.SANDBOX_UNAVAILABLE
        assert "Static syntax" in message

    def test_static_only_verdict_completes_without_retry(self):
        state = initial_state("fn", "def fn():\n    return 1", "python", 90.0, {})
        state["patched_code"] = "def fn():\n    return 2"

        with patch(
            "vulnguard.agents.judge_agent._validate",
            return_value=(JudgeVerdict.SANDBOX_UNAVAILABLE, "static only"),
        ):
            result = judge_agent_node(state)

        assert result["pipeline_status"] == "COMPLETE"
        assert result["judge_verdict"] == "SANDBOX_UNAVAILABLE"
        assert "attempt_number" not in result
        assert result["build_success"] is False
        assert result["test_success"] is False
        assert result["exploit_blocked"] is False
