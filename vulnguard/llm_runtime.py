"""Offline-safe LiteLLM initialization."""

from __future__ import annotations

import importlib.util
import json
import os
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cache" / "tiktoken"
_USAGE_LOG = Path(__file__).resolve().parent.parent / "data" / "llm_usage.jsonl"
_USAGE_LOCK = threading.Lock()
_PREPARED = False


def _prepare_litellm_environment() -> None:
    """Use LiteLLM's bundled metadata and repair CRLF-corrupted token caches."""
    global _PREPARED
    if _PREPARED:
        return

    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    if "CUSTOM_TIKTOKEN_CACHE_DIR" not in os.environ:
        spec = importlib.util.find_spec("litellm")
        if spec and spec.origin:
            bundled = Path(spec.origin).parent / "litellm_core_utils" / "tokenizers"
            cache_files = [
                path
                for path in bundled.iterdir()
                if path.is_file()
                and len(path.name) == 40
                and all(char in string.hexdigits for char in path.name)
            ] if bundled.is_dir() else []
            if cache_files:
                _CACHE_DIR.mkdir(parents=True, exist_ok=True)
                for source in cache_files:
                    target = _CACHE_DIR / source.name
                    content = source.read_bytes().replace(b"\r\n", b"\n")
                    if not target.exists() or target.read_bytes() != content:
                        target.write_bytes(content)
                os.environ["CUSTOM_TIKTOKEN_CACHE_DIR"] = str(_CACHE_DIR)
                os.environ["TIKTOKEN_CACHE_DIR"] = str(_CACHE_DIR)

    _PREPARED = True


def completion(**kwargs: Any):
    """Call LiteLLM after configuring its offline metadata caches."""
    _prepare_litellm_environment()
    from litellm import completion as litellm_completion

    started = time.perf_counter()
    response = litellm_completion(**kwargs)
    latency_ms = (time.perf_counter() - started) * 1000
    _record_usage(response, str(kwargs.get("model", "unknown")), latency_ms)
    return response


def _usage_value(usage: Any, key: str) -> int:
    if isinstance(usage, dict):
        return int(usage.get(key, 0) or 0)
    return int(getattr(usage, key, 0) or 0)


def _record_usage(response: Any, requested_model: str, latency_ms: float = 0.0) -> None:
    """Append token and cost metadata without storing prompts or responses."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return

    hidden = getattr(response, "_hidden_params", {}) or {}
    cost = hidden.get("response_cost")
    if cost is None:
        try:
            from litellm import completion_cost

            cost = completion_cost(completion_response=response)
        except Exception:
            cost = None

    provider, _, model_name = requested_model.partition("/")
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": provider if model_name else "unknown",
        "model": model_name or provider,
        "input_tokens": _usage_value(usage, "prompt_tokens"),
        "output_tokens": _usage_value(usage, "completion_tokens"),
        "total_tokens": _usage_value(usage, "total_tokens"),
        "estimated_cost_usd": float(cost) if cost is not None else None,
        "latency_ms": round(latency_ms, 3),
    }
    _USAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with _USAGE_LOCK, _USAGE_LOG.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, separators=(",", ":")) + "\n")


def usage_summary() -> list[dict[str, Any]]:
    """Aggregate locally recorded LLM usage by provider and model."""
    totals: dict[tuple[str, str], dict[str, Any]] = {}
    if not _USAGE_LOG.exists():
        return []

    for line in _USAGE_LOG.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = (record.get("provider", "unknown"), record.get("model", "unknown"))
        total = totals.setdefault(
            key,
            {
                "provider": key[0],
                "model": key[1],
                "calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "estimated_cost_usd": 0.0,
                "latency_ms": 0.0,
            },
        )
        total["calls"] += 1
        for field in ("input_tokens", "output_tokens", "total_tokens"):
            total[field] += int(record.get(field, 0) or 0)
        total["estimated_cost_usd"] += float(record.get("estimated_cost_usd") or 0.0)
        total["latency_ms"] += float(record.get("latency_ms") or 0.0)

    rows = sorted(totals.values(), key=lambda item: (item["provider"], item["model"]))
    for row in rows:
        row["avg_latency_ms"] = row.pop("latency_ms") / row["calls"]
    return rows
