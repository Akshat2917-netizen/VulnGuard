import os

import vulnguard.llm_runtime as runtime


def test_litellm_environment_uses_normalized_local_tokenizers(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(runtime, "_PREPARED", False)
    monkeypatch.delenv("CUSTOM_TIKTOKEN_CACHE_DIR", raising=False)
    monkeypatch.delenv("TIKTOKEN_CACHE_DIR", raising=False)
    monkeypatch.delenv("LITELLM_LOCAL_MODEL_COST_MAP", raising=False)

    runtime._prepare_litellm_environment()

    cache_files = list(tmp_path.iterdir())
    assert cache_files
    assert all(b"\r\n" not in path.read_bytes() for path in cache_files)
    assert os.environ["CUSTOM_TIKTOKEN_CACHE_DIR"] == str(tmp_path)
    assert os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"
