"""
Tree-sitter parser for extracting CodeUnits from source files.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import tree_sitter_python
from tree_sitter import Language, Parser, Node, Query, QueryCursor

logger = logging.getLogger(__name__)

# Initialize Python Language and Parser
PY_LANGUAGE = Language(tree_sitter_python.language())
parser = Parser(PY_LANGUAGE)

@dataclass
class CodeUnit:
    """Represents a chunked function/method from a source file."""
    file_path: str
    function_name: str
    class_name: Optional[str]
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    raw_source: str
    language: str
    imports: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)


def _get_node_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")


def parse_python_file(file_path: str, source_code: str) -> list[CodeUnit]:
    """Parse a Python file and extract all functions as CodeUnits."""
    source_bytes = source_code.encode("utf-8")
    tree = parser.parse(source_bytes)
    root_node = tree.root_node

    # Query to find function definitions
    query_str = """
    (function_definition
      name: (identifier) @func.name
    ) @func.def
    """
    query = Query(PY_LANGUAGE, query_str)
    
    # Simple query for imports to attach as context
    import_query_str = """
    (import_statement) @import
    (import_from_statement) @import_from
    """
    import_query = Query(PY_LANGUAGE, import_query_str)
    
    imports = []
    # Using QueryCursor for latest tree-sitter version (>= 0.22)
    import_qc = QueryCursor(import_query)
    import_matches = import_qc.matches(root_node)
    
    for _, match_dict in import_matches:
        for name, nodes in match_dict.items():
            for node in nodes:
                imports.append(_get_node_text(node, source_bytes))

    code_units = []
    
    qc = QueryCursor(query)
    matches = qc.matches(root_node)
    
    # match_dict is like {'func.def': [Node], 'func.name': [Node]}
    for _, match_dict in matches:
        f_nodes = match_dict.get("func.def", [])
        name_nodes = match_dict.get("func.name", [])
        
        if not f_nodes or not name_nodes:
            continue
            
        f_node = f_nodes[0]
        name_node = name_nodes[0]
            
        func_name = _get_node_text(name_node, source_bytes)
        
        # Check if it's inside a class
        class_name = None
        parent = f_node.parent
        while parent:
            if parent.type == "class_definition":
                c_name_node = parent.child_by_field_name("name")
                if c_name_node:
                    class_name = _get_node_text(c_name_node, source_bytes)
                break
            parent = parent.parent
            
        # Find callees
        callees = []
        call_query_str = "(call function: (identifier) @call.name)"
        try:
            call_query = Query(PY_LANGUAGE, call_query_str)
            call_qc = QueryCursor(call_query)
            call_matches = call_qc.matches(f_node)
            for _, call_match_dict in call_matches:
                for c_nodes in call_match_dict.values():
                    for c_node in c_nodes:
                        callees.append(_get_node_text(c_node, source_bytes))
        except Exception as e:
            logger.debug(f"Error extracting callees: {e}")
            
        cu = CodeUnit(
            file_path=file_path,
            function_name=func_name,
            class_name=class_name,
            start_byte=f_node.start_byte,
            end_byte=f_node.end_byte,
            # tree-sitter lines are 0-indexed
            start_line=f_node.start_point[0] + 1,
            end_line=f_node.end_point[0] + 1,
            raw_source=_get_node_text(f_node, source_bytes),
            language="python",
            imports=list(set(imports)),
            callees=list(set(callees))
        )
        code_units.append(cu)
        
    return code_units
