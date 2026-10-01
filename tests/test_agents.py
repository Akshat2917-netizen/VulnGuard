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
    _exploit_validation_error,
    red_agent_node,
    _validate_exploit_language,
    _sanitize_exploit,
)
from vulnguard.agents.blue_agent import (
    _check_ast_loc_delta,
    _insecure_patch_reason,
    blue_agent_node,
)
from vulnguard.agents.judge_agent import (
    JudgeVerdict,
    _run_tests,
    _truncate_error_logs,
    _validate,
    judge_agent_node,
)
from vulnguard.sandbox.docker_runner import CommandResult


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

    def test_rejects_harness_that_redefines_python_target(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness="def update_user_status(value):\n    print(value)",
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("database.py:update_user_status", "pass", "python", 90.0, {})
        state["file_path"] = "database.py"

        assert "redefines target" in _exploit_validation_error(report, state)

    def test_accepts_harness_that_imports_python_target(self, tmp_path):
        package = tmp_path / "vuln_taint_flow"
        package.mkdir()
        target = package / "database.py"
        target.write_text(
            "class Database:\n"
            "    def update_user_status(self, value):\n"
            "        pass\n"
        )
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "from vuln_taint_flow.database import Database\n"
                "print(Database)"
            ),
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_taint_flow/database.py:update_user_status", "pass", "python", 90.0, {})
        state["file_path"] = str(target)
        state["repo_root"] = str(tmp_path)

        assert _exploit_validation_error(report, state) is None

    def test_rejects_marker_embedded_in_exploit_input(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "from vuln_cmdi import ping_host\n"
                "ping_host('localhost; echo DEFECT_TRIGGERED')"
            ),
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_cmdi.py:ping_host", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_cmdi.py"

        assert "embedded in exploit input" in _exploit_validation_error(report, state)

    def test_rejects_harness_without_success_regex(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness="from vuln_sqli import get_user",
        )
        state = initial_state("vuln_sqli.py:get_user", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_sqli.py"

        assert "no expected_stdout_regex" in _exploit_validation_error(report, state)

    def test_rejects_python_harness_for_c_target(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness="import subprocess\nprint('DEFECT_TRIGGERED')",
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_buffer.c:process_data", "pass", "c", 90.0, {})

        assert "does not match target language" in _exploit_validation_error(report, state)

    def test_rejects_generic_exception_as_exploit_success(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "from vuln_sqli import get_user\n"
                "try:\n    get_user('x')\n"
                "except Exception:\n    print('DEFECT_TRIGGERED')"
            ),
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_sqli.py:get_user", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_sqli.py"

        assert "false positives" in _exploit_validation_error(report, state)


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

    def test_rejects_command_injection_patch_that_keeps_os_system(self):
        state = initial_state("vuln_cmdi.py:ping_host", "pass", "python", 90.0, {})
        state["red_report"] = {"vulnerability_type": "COMMAND_INJECTION"}

        reason = _insecure_patch_reason(state, "os.system(' '.join(command))")

        assert "still invokes a shell" in reason

    def test_successful_retry_clears_previous_judge_error(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host(host):\n    return 0", "python", 90.0, {})
        state["red_report"] = {"vulnerability_type": "COMMAND_INJECTION"}
        state["judge_verdict"] = "NEW_VULNERABILITY_INTRODUCED"
        state["error_logs"] = "old failure"
        response = json.dumps(
            {
                "patched_code": "def ping_host(host):\n    return os.spawnvp(os.P_WAIT, 'ping', ['ping', host])",
                "changes_summary": "Use shell-free execution",
                "preserved_interface": True,
                "new_dependencies_added": False,
                "justification": "Arguments are not interpreted by a shell",
            }
        )

        with patch("vulnguard.agents.blue_agent._call_llm", return_value=response):
            result = blue_agent_node(state)

        assert result["judge_verdict"] == ""
        assert result["error_logs"] == ""


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

    def test_no_collected_tests_are_skipped(self):
        state = initial_state("fn", "def fn():\n    return 1", "python", 90.0, {})
        runner = MagicMock()
        runner.run_tests.return_value = CommandResult(
            success=False,
            exit_code=5,
            stdout="no tests ran in 0.00s",
            stderr="",
        )

        with patch("vulnguard.sandbox.docker_runner.DockerRunner", return_value=runner):
            success, message = _run_tests(state)

        assert success is True
        assert "skipped" in message

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
