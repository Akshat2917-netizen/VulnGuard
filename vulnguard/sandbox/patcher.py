"""
AST Span Patcher — reliably replaces function code via exact byte offsets.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def apply_patch(file_path: str, start_byte: int, end_byte: int, new_code: str) -> None:
    """
    Replaces the exact byte span in a file with the new patched code.
    This avoids the flakiness of LLM-generated git-diffs.
    
    Args:
        file_path: The absolute or relative path to the file to modify.
        start_byte: The tree-sitter start byte of the original function.
        end_byte: The tree-sitter end byte of the original function.
        new_code: The raw string of the new function code.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Cannot patch missing file: {path}")

    # Read the file as raw bytes to ensure exact index matching
    original_bytes = path.read_bytes()
    
    # Ensure indices are within bounds
    if start_byte < 0 or end_byte > len(original_bytes) or start_byte > end_byte:
        raise ValueError(f"Invalid byte span [{start_byte}, {end_byte}) for file of size {len(original_bytes)}")

    # We expect the LLM might give us markdown formatting (e.g. ```python ... ```)
    # We should strip that if present before applying the splice.
    cleaned_code = new_code.strip()
    if cleaned_code.startswith("```"):
        lines = cleaned_code.splitlines()
        if len(lines) > 2 and lines[-1].strip() == "```":
            # Strip the first line (e.g. ```python) and last line (```)
            cleaned_code = "\n".join(lines[1:-1])
            
    # Also strip out any leading/trailing whitespace to avoid duplicating newlines
    # BUT wait, the LLM patch might need the exact indentation if it's a Python class method.
    # Actually, the LLM should generate the function with correct indentation if prompted well.
    # Let's just encode to bytes.
    new_bytes = cleaned_code.encode("utf-8")

    # Splice: Before the function + new function + after the function
    before = original_bytes[:start_byte]
    after = original_bytes[end_byte:]
    
    patched_bytes = before + new_bytes + after
    
    # Write back
    path.write_bytes(patched_bytes)
    logger.info("Successfully spliced %d bytes into %s at [%d:%d]", len(new_bytes), path.name, start_byte, end_byte)

