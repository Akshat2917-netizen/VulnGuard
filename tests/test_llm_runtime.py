import os
from types import SimpleNamespace

import vulnguard.llm_runtime as llm_runtime


def test_litellm_environment_uses_normalized_local_tokenizers(monkeypatch, tmp_path):
    monkeypatch.setattr(llm_runtime, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm_runtime, "_PREPARED", False)
    monkeypatch.delenv("CUSTOM_TIKTOKEN_CACHE_DIR", raising=False)
    monkeypatch.delenv("TIKTOKEN_CACHE_DIR", raising=False)
    monkeypatch.delenv("LITELLM_LOCAL_MODEL_COST_MAP", raising=False)

    llm_runtime._prepare_litellm_environment()

    cache_files = list(tmp_path.iterdir())
    assert cache_files
    assert all(b"\r\n" not in path.read_bytes() for path in cache_files)
    assert os.environ["CUSTOM_TIKTOKEN_CACHE_DIR"] == str(tmp_path)
    assert os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"


def test_usage_log_records_and_aggregates_metadata(tmp_path, monkeypatch):
    usage_log = tmp_path / "usage.jsonl"
    monkeypatch.setattr(llm_runtime, "_USAGE_LOG", usage_log)
    response = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=120, completion_tokens=30, total_tokens=150),
        _hidden_params={"response_cost": 0.00125},
    )

    llm_runtime._record_usage(response, "gemini/gemini-3.8-flash", latency_ms=250.0)
    summary = llm_runtime.usage_summary()

    assert summary == [
        {
            "provider": "gemini",
            "model": "gemini-3.8-flash",
            "calls": 1,
            "input_tokens": 120,
            "output_tokens": 30,
            "total_tokens": 150,
            "estimated_cost_usd": 0.00125,
            "avg_latency_ms": 250.0,
        }
    ]
    assert "prompt" not in usage_log.read_text()
