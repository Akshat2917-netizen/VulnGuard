"""
Red Agent — Threat analyzer & PoC exploit generator.

Receives high-risk flagged code with context, analyzes vulnerabilities,
and generates structured threat reports with synthetic PoC exploit payloads.
Includes NO_VULNERABILITY_FOUND exit state (Section 4.1 FP exit) and
language-match validation (EC-7.2).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from pydantic import BaseModel, Field
from typing import Optional

from vulnguard.agents.state import VulnGuardState
from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# ── Dangerous payload patterns (Section 4.3) ─────────────────────────────
_DANGEROUS_PATTERNS = re.compile(
    r"rm\s+-rf\s+/|fork\s*\(\s*\)|:\(\)\s*\{|dd\s+if=|mkfs\.|"
    r"shutdown|reboot|format\s+[cCdD]:",
    re.IGNORECASE,
)

# Language → expected code markers for exploit validation (EC-7.2)
_LANGUAGE_MARKERS = {
    "c": [r"#include|int\s+main|printf|malloc|free"],
    "cpp": [r"#include|int\s+main|std::|cout|cin"],
    "python": [r"def\s+|import\s+|print\s*\(|if\s+__name__"],
    "java": [r"public\s+class|System\.out|import\s+java"],
    "javascript": [r"const\s+|let\s+|var\s+|function\s+|require\s*\(|console\.log"],
}


# ── Pydantic output schema (enforced structured output) ──────────────────

class RedAgentReport(BaseModel):
    """Structured threat report from the Red Agent."""

    vulnerability_found: bool = Field(description="Whether a vulnerability was identified")
    vulnerability_type: Optional[str] = Field(None, description="E.g. SQL_INJECTION, BUFFER_OVERFLOW, XSS")
    cwe_id: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    severity: Optional[str] = Field(None, description="CRITICAL, HIGH, MEDIUM, or LOW")
    affected_lines: Optional[list[int]] = Field(None, description="Line numbers containing the defect")
    explanation: Optional[str] = Field(None, description="Technical explanation of the defect")
    exploit_type: Optional[str] = Field(None, description="Language of the exploit: python_script, c_harness, shell_command")
    exploit_code_harness: Optional[str] = Field(None, description="Executable proof-of-concept code")
    expected_stdout_regex: Optional[str] = Field(None, description="Regex to match successful test output")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence score 0.0-1.0")


# ── Prompt construction ──────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a senior software engineer and QA specialist focusing on code correctness and data integrity.

Your task is to analyze the provided function for data flow defects (e.g., untrusted string interpolation in queries, out-of-bounds memory access).

RULES:
1. If the function operates correctly on all inputs, set vulnerability_found=false.
2. If a data flow defect exists (such as improper string interpolation), provide a benign Python script that acts as a failing test case to demonstrate the flaw.
3. IMPORTANT SAFETY RULE: Do NOT write malicious payloads (no DROP TABLE, no XSS alerts, no reverse shells). Instead, use benign inputs like `"active'"` or `"test_string"` that simply trigger a syntax error or unexpected behavior to prove the input is unsanitized.
4. The test MUST produce detectable stdout output (e.g. print "DEFECT_TRIGGERED") when the defect is triggered.
5. Do NOT perform any destructive system operations in the test case.
6. The test MUST execute the target from the supplied workspace. Do not copy the target function into the test, because the Judge must run the same test against both the original and patched source.

You must output valid JSON data containing your analysis. Do NOT output the schema itself. Your JSON output MUST conform to the following schema:
{schema}
"""

_USER_PROMPT = """\
## Target Function
File: {file_path}
Language: {language}

```{language}
{code}
```

## Context Bundle
{context}

Analyze this function for data integrity defects. If safe, set vulnerability_found=false.
"""


def _build_prompt(state: VulnGuardState) -> list[dict[str, str]]:
    """Build the Red Agent prompt messages."""
    from vulnguard.data.context_gatherer import ContextBundle

    ctx_dict = state.get("context_bundle", {})
    ctx = ContextBundle(**ctx_dict) if ctx_dict else ContextBundle()
    context_text = ctx.to_prompt_text() if ctx_dict else "(No context available)"

    schema_json = json.dumps(RedAgentReport.model_json_schema(), indent=2)

    return [
        {
            "role": "system",
            "content": _SYSTEM_PROMPT.format(
                language=state["language"],
                schema=schema_json,
            ),
        },
        {
            "role": "user",
            "content": _USER_PROMPT.format(
                risk_score=state["risk_score"],
                file_path=state.get("file_path", "unknown"),
                language=state["language"],
                code=state["original_code"],
                context=context_text,
            ),
        },
    ]


# ── LLM invocation with retry ────────────────────────────────────────────

def _call_llm(messages: list[dict], risk_score: float = 100.0, retries: int = 3) -> str:
    """Call LLM with exponential backoff and severity-based model routing.

    Uses cfg.routing to pick the right model tier based on risk_score:
      - score >= 80 → high-tier model (e.g. Gemini 3.1 Pro, Opus 4.6)
      - score 65-79 → medium-tier model (e.g. Gemini Flash, Sonnet 4.6)
    """
    if cfg.llm.mock_mode:
        logger.info("Mock LLM enabled. Returning synthetic Red Agent response.")
        return """
        {
          "vulnerability_found": true,
          "vulnerability_type": "MOCK_VULN",
          "cwe_id": "CWE-999",
          "severity": "HIGH",
          "affected_lines": [1, 2],
          "explanation": "This is a mock vulnerability found by the mock Red Agent.",
          "exploit_type": "python_script",
          "exploit_code_harness": "def exploit():\\n    print('EXPLOIT_SUCCESS')\\nexploit()",
          "expected_stdout_regex": "EXPLOIT_SUCCESS",
          "confidence": 0.95
        }
        """

    provider, model_name = cfg.routing.get_model_for_score(risk_score)
    model = f"{provider}/{model_name}"
    from vulnguard.llm_runtime import completion

    logger.info("Model routing: risk=%.1f → %s", risk_score, model)

    for attempt in range(retries):
        try:
            response = completion(
                model=model,
                messages=messages,
                temperature=cfg.llm.temperature,
                max_tokens=cfg.llm.max_tokens,
                response_format={"type": "json_object"},
            )
            raw_response = response.choices[0].message.content
            
            # Detect safety filter refusal
            if "I cannot fulfill your request" in raw_response or "I am unable to perform" in raw_response:
                logger.warning("LLM safety filter triggered, but running on Groq so we shouldn't see this.")
            
            # Extract JSON if the model wrapped it in markdown blocks
            if "```json" in raw_response:
                raw_response = raw_response.split("```json")[1].split("```")[0].strip()
            elif "```" in raw_response:
                raw_response = raw_response.split("```")[1].split("```")[0].strip()
                
            return raw_response
        except Exception as exc:
            import litellm
            delay = cfg.llm.retry_base_delay_seconds * (2 ** attempt)
            
            if isinstance(exc, litellm.exceptions.RateLimitError):
                logger.warning("Rate limit hit. Retrying in %.1fs...", delay)
            else:
                logger.warning("LLM call failed (attempt %d/%d): %s. Retrying in %.1fs", attempt + 1, retries, exc, delay)
                
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                raise


# ── Validation ────────────────────────────────────────────────────────────

def _validate_exploit_language(report: RedAgentReport, target_language: str) -> bool:
    """Check if exploit code matches target language (EC-7.2)."""
    if not report.exploit_code_harness:
        return True

    markers = _LANGUAGE_MARKERS.get(target_language, [])
    if not markers:
        return True  # Unknown language — skip check

    pattern = "|".join(markers)
    return bool(re.search(pattern, report.exploit_code_harness))


def _sanitize_exploit(report: RedAgentReport) -> RedAgentReport:
    """Remove dangerous patterns from exploit code (Section 4.3)."""
    if report.exploit_code_harness and _DANGEROUS_PATTERNS.search(report.exploit_code_harness):
        logger.warning("Dangerous payload detected in exploit — sanitizing")
        report.exploit_code_harness = "// DANGEROUS PAYLOAD REMOVED — re-prompt needed"
        report.confidence = 0.0
    return report


# ── LangGraph node function ──────────────────────────────────────────────

def red_agent_node(state: VulnGuardState) -> dict[str, Any]:
    """LangGraph node: Run Red Agent analysis.

    Returns partial state update dict.
    """
    logger.info("🔴 Red Agent analyzing function: %s", state["function_id"])
    start = time.time()

    messages = _build_prompt(state)
    raw_response = _call_llm(messages, risk_score=state.get("risk_score", 100.0))

    # Parse structured output
    def _extract_json(text: str) -> str:
        if not text:
            return ""
        text = text.strip()
        if text.startswith("```"):
            import re
            match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                return match.group(1)
        return text

    clean_response = _extract_json(raw_response)

    try:
        report = RedAgentReport.model_validate_json(clean_response)
    except Exception:
        # Fallback: try extracting JSON from response
        try:
            data = json.loads(clean_response)
            if "vulnerability_found" not in data and isinstance(data.get("properties"), dict):
                data = data["properties"]
            report = RedAgentReport(**data)
        except Exception as exc:
            logger.error("Failed to parse Red Agent response: %s", exc)
            logger.error("RAW RESPONSE: %r", raw_response)
            logger.error("CLEAN RESPONSE: %r", clean_response)
            return {
                "red_report": {"raw": raw_response, "parse_error": str(exc)},
                "vulnerability_found": False,
                "pipeline_status": "RED_PARSE_ERROR",
                "timestamps": {**state.get("timestamps", {}), "red_end": time.time()},
            }

    # Sanitize dangerous payloads
    report = _sanitize_exploit(report)

    # Validate exploit language match (EC-7.2)
    if report.vulnerability_found and not _validate_exploit_language(report, state["language"]):
        logger.warning("Exploit language mismatch — re-prompting once")
        messages.append({
            "role": "user",
            "content": f"Your test code does not match the target language ({state['language']}). "
            f"Please regenerate the test in {state['language']}.",
        })
        try:
            raw_retry = _call_llm(messages, risk_score=state.get("risk_score", 100.0))
            # Extract JSON if wrapped
            if "```json" in raw_retry:
                raw_retry = raw_retry.split("```json")[1].split("```")[0].strip()
            elif "```" in raw_retry:
                raw_retry = raw_retry.split("```")[1].split("```")[0].strip()
                
            report = RedAgentReport.model_validate_json(raw_retry)
            report = _sanitize_exploit(report)
        except Exception:
            pass  # Use original if re-prompt fails

    elapsed = time.time() - start
    logger.info(
        "🔴 Red Agent result: vulnerability_found=%s, type=%s, severity=%s (%.1fs)",
        report.vulnerability_found,
        report.vulnerability_type,
        report.severity,
        elapsed,
    )

    return {
        "red_report": report.model_dump(),
        "vulnerability_found": report.vulnerability_found,
        "exploit_harness": report.exploit_code_harness,
        "exploit_type": report.exploit_type,
        "expected_stdout_regex": report.expected_stdout_regex,
        "pipeline_status": "RED_COMPLETE",
        "timestamps": {**state.get("timestamps", {}), "red_end": time.time()},
    }
