"""Offline-safe LiteLLM initialization."""

from __future__ import annotations

import importlib.util
import os
import string
from pathlib import Path
from typing import Any


_CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cache" / "tiktoken"
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

    return litellm_completion(**kwargs)
