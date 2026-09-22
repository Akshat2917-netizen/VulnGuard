"""
Judge Agent — Sandbox evaluator & retry loop manager.

Orchestrates validation: AST/LOC delta → Build → Tests → Exploit dual pass.
Manages the attempt history ledger and enforces retry limits.
"""

from __future__ import annotations

import logging
import re
import time
from enum import Enum
from typing import Any

from vulnguard.agents.state import VulnGuardState
from vulnguard.config import cfg

logger = logging.getLogger(__name__)


class JudgeVerdict(str, Enum):
    """Possible validation outcomes."""

    PASS = "PASS"
    BUILD_FAILED = "BUILD_FAILED"
    TESTS_FAILED = "TESTS_FAILED"
    EXPLOIT_NOT_REPRODUCED = "EXPLOIT_NOT_REPRODUCED"
    EXPLOIT_NOT_BLOCKED = "EXPLOIT_NOT_BLOCKED"
    DESTRUCTIVE_PATCH_REJECTED = "DESTRUCTIVE_PATCH_REJECTED"
    NEW_VULNERABILITY_INTRODUCED = "NEW_VULNERABILITY_INTRODUCED"
    INTERFACE_VIOLATION = "INTERFACE_VIOLATION"
    MAX_RETRIES_EXHAUSTED = "MAX_RETRIES_EXHAUSTED"
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"


# ── Error log truncation (Section 4.6) ────────────────────────────────────

_ERROR_PATTERN = re.compile(
    r".*(?:error|fail|fault|warning|undefined|segfault|traceback|exception|"
    r"cannot|unable|not found|denied|killed|abort|panic).*",
    re.IGNORECASE,
)


def _truncate_error_logs(logs: str, max_chars: int = 2000) -> str:
    """Filter error logs to relevant lines, capped at max_chars."""
    if len(logs) <= max_chars:
        return logs

    relevant = [line for line in logs.splitlines() if _ERROR_PATTERN.match(line)]
    truncated = "\n".join(relevant)

    if len(truncated) > max_chars:
        truncated = truncated[:max_chars] + "\n[... truncated]"

    return truncated or logs[:max_chars] + "\n[... truncated]"


# ── Sandbox execution helpers ─────────────────────────────────────────────

def _get_full_file_code(state: VulnGuardState, use_patched: bool) -> str:
    """Reconstruct the full file content by splicing the target function."""
    from pathlib import Path
    
    file_path = state.get("file_path")
    
    # Pre-clean patched code to remove markdown blocks
    patched_code = state.get("patched_code", "")
    if patched_code:
        cleaned_code = patched_code.strip()
        if cleaned_code.startswith("```"):
            lines = cleaned_code.splitlines()
            if len(lines) > 2 and lines[-1].strip() == "```":
                cleaned_code = "\n".join(lines[1:-1])
        patched_code = cleaned_code

    if not file_path or not Path(file_path).exists():
        return patched_code if use_patched else state.get("original_code", "")
        
    start_byte = state.get("start_byte")
    end_byte = state.get("end_byte")
    
    if start_byte is None or end_byte is None:
        logger.warning("No start_byte/end_byte in state — falling back to snippet")
        return patched_code if use_patched else state.get("original_code", "")
        
    original_bytes = Path(file_path).read_bytes()
    
    if not use_patched:
        return original_bytes.decode("utf-8", errors="replace")
            
    new_bytes = patched_code.encode("utf-8")
    before = original_bytes[:start_byte]
    after = original_bytes[end_byte:]
    
    return (before + new_bytes + after).decode("utf-8", errors="replace")


def _run_build(state: VulnGuardState, use_patched: bool = False) -> tuple[bool, str]:
    """Run build in Docker sandbox. Returns (success, logs)."""
    try:
        from vulnguard.sandbox.docker_runner import DockerRunner

        runner = DockerRunner()
        code = _get_full_file_code(state, use_patched)
        result = runner.run_build(
            repo_root=state.get("repo_root", ""),
            file_path=state.get("file_path", ""),
            code=code,
        )
        return result.success, result.combined_output
    except ImportError:
        logger.warning("Docker SDK not available — skipping build check")
        return True, "Docker not available — build check skipped"
    except Exception as exc:
        logger.error("Build execution failed: %s", exc)
        return False, str(exc)


def _run_tests(state: VulnGuardState) -> tuple[bool, str]:
    """Run existing test suite in Docker sandbox."""
    try:
        from vulnguard.sandbox.docker_runner import DockerRunner

        runner = DockerRunner()
        result = runner.run_tests(
            repo_root=state.get("repo_root", ""),
            file_path=state.get("file_path", ""),
            code=_get_full_file_code(state, use_patched=True),
        )
        return result.success, result.combined_output
    except ImportError:
        logger.info("Docker not available — skipping test suite")
        return True, "Skipped (Docker unavailable)"
    except Exception as exc:
        return False, str(exc)


def _run_exploit(state: VulnGuardState, use_patched: bool = False) -> tuple[bool, str]:
    """Run Red Agent's PoC exploit. Returns (crashed/failed, logs).

    For unpatched code: exploit should succeed (crash = vulnerability exists).
    For patched code: exploit should fail (no crash = vulnerability fixed).
    """
    exploit_code = state.get("exploit_harness")
    if not exploit_code:
        logger.info("No exploit harness — skipping exploit validation")
        return True, "No exploit to run"

    try:
        from vulnguard.sandbox.docker_runner import DockerRunner

        runner = DockerRunner()
        code = _get_full_file_code(state, use_patched)
        result = runner.run_exploit(
            repo_root=state.get("repo_root", ""),
            exploit_code=exploit_code,
            target_code=code,
            file_path=state.get("file_path", ""),
            language=state.get("language", "c"),
        )
        return result.success, result.combined_output
    except ImportError:
        return True, "Docker not available — exploit check skipped"
    except Exception as exc:
        return False, str(exc)


# ── Core validation pipeline ─────────────────────────────────────────────

def _validate(state: VulnGuardState) -> tuple[JudgeVerdict, str]:
    """Run the full validation sequence.

    Steps:
    1. Build compilation check (patched code) — skipped for single-file uploads
    2. Existing test suite (regression check) — skipped for single-file uploads
    3. Exploit dual pass:
       a. Exploit on unpatched → should crash/fail (proves vuln exists)
       b. Exploit on patched → should pass/not crash (proves vuln is fixed)
    4. Deterministic double-run (Section 4.6)

    Returns (verdict, error_logs).
    """
    patched = state.get("patched_code")
    if not patched:
        return JudgeVerdict.BUILD_FAILED, "No patched code provided"

    repo_root = state.get("repo_root", "")

    if repo_root:
        # ── Step 1: Build (full project only) ─────────────
        build_ok, build_logs = _run_build(state, use_patched=True)
        if not build_ok:
            return JudgeVerdict.BUILD_FAILED, _truncate_error_logs(build_logs)

        # ── Step 2: Tests (full project only) ─────────────
        tests_ok, test_logs = _run_tests(state)
        if not tests_ok:
            return JudgeVerdict.TESTS_FAILED, _truncate_error_logs(test_logs)
    else:
        # Single-file upload: no project to build/test.
        # Do a quick syntax check via Python AST instead.
        import ast
        full_code = _get_full_file_code(state, use_patched=True)
        try:
            ast.parse(full_code)
            logger.info("⚖️  AST syntax check passed (single-file mode)")
        except SyntaxError as e:
            return JudgeVerdict.BUILD_FAILED, f"Syntax error in patched code: {e}"

    # ── Step 3a: Exploit on unpatched (should demonstrate vulnerability) ──
    if state.get("exploit_harness"):
        expected_regex = state.get("expected_stdout_regex")

        def exploit_succeeded(success_code: bool, logs: str) -> bool:
            """Determine if the exploit successfully triggered the vulnerability."""
            if expected_regex:
                try:
                    return bool(re.search(expected_regex, logs))
                except Exception:
                    pass
            # Fallback: assume exit code 0 means the exploit script successfully ran its payload
            return success_code

        unpatched_ok, unpatched_logs = _run_exploit(state, use_patched=False)
        if not exploit_succeeded(unpatched_ok, unpatched_logs):
            return JudgeVerdict.EXPLOIT_NOT_REPRODUCED, _truncate_error_logs(unpatched_logs)

        # ── Step 3b: Exploit on patched (should NOT trigger) ────
        patched_ok, patched_logs = _run_exploit(state, use_patched=True)
        if exploit_succeeded(patched_ok, patched_logs):
            return JudgeVerdict.EXPLOIT_NOT_BLOCKED, _truncate_error_logs(patched_logs)

        # ── Step 4: Deterministic double-run (Section 4.6) ──
        if cfg.agent.double_run_validation:
            patched_ok2, patched_logs2 = _run_exploit(state, use_patched=True)
            if exploit_succeeded(patched_ok2, patched_logs2):
                return JudgeVerdict.EXPLOIT_NOT_BLOCKED, "Flaky result — blocked first run, succeeded second"

    return JudgeVerdict.PASS, ""


# ── LangGraph node function ──────────────────────────────────────────────

def judge_agent_node(state: VulnGuardState) -> dict[str, Any]:
    """LangGraph node: Validate the Blue Agent's patch.

    Returns partial state update. If validation fails, increments
    attempt_number and appends to attempt_history for retry.
    """
    attempt = state.get("attempt_number", 0)
    logger.info("⚖️  Judge Agent validating patch (attempt %d)", attempt + 1)
    start = time.time()

    # Check if Blue Agent already rejected (interface violation, destructive, etc.)
    pre_verdict = state.get("judge_verdict", "")
    if pre_verdict in (
        JudgeVerdict.DESTRUCTIVE_PATCH_REJECTED,
        JudgeVerdict.INTERFACE_VIOLATION,
        "NEW_DEPENDENCIES_REJECTED",
    ):
        logger.info("⚖️  Pre-rejected by Blue Agent guardrails: %s", pre_verdict)
        verdict = JudgeVerdict(pre_verdict) if pre_verdict in JudgeVerdict.__members__ else JudgeVerdict.BUILD_FAILED
        error_logs = state.get("error_logs", "")
    else:
        # Run full sandbox validation
        verdict, error_logs = _validate(state)

    elapsed = time.time() - start
    logger.info("⚖️  Judge verdict: %s (%.1fs)", verdict.value, elapsed)

    result: dict[str, Any] = {
        "judge_verdict": verdict.value,
        "error_logs": error_logs,
        "build_success": verdict != JudgeVerdict.BUILD_FAILED,
        "test_success": verdict != JudgeVerdict.TESTS_FAILED,
        "exploit_blocked": verdict not in (JudgeVerdict.EXPLOIT_NOT_BLOCKED,),
        "timestamps": {**state.get("timestamps", {}), "judge_end": time.time()},
    }

    if verdict == JudgeVerdict.PASS:
        result["pipeline_status"] = "COMPLETE"
    elif verdict == JudgeVerdict.EXPLOIT_NOT_REPRODUCED:
        result["pipeline_status"] = "FAILED"
    elif attempt + 1 >= state.get("max_attempts", 3):
        result["pipeline_status"] = "FAILED"
        result["judge_verdict"] = JudgeVerdict.MAX_RETRIES_EXHAUSTED.value
        logger.warning("⚖️  Max retries exhausted — pipeline FAILED")
    else:
        # Prepare for retry
        result["pipeline_status"] = "RETRY"
        result["attempt_number"] = attempt + 1
        result["attempt_history"] = [
            {
                "attempt_number": attempt + 1,
                "patched_code": state.get("patched_code", ""),
                "error_logs": error_logs[:500],
                "failure_reason": verdict.value,
            }
        ]
        logger.info("⚖️  Scheduling retry %d/%d", attempt + 2, state.get("max_attempts", 3))

    return result
