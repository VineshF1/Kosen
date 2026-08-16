from __future__ import annotations

from .diff_parser import parse_diff, merge_adjacent_ranges, DiffRange, ParsedDiff, get_ranges_for_file
from .ast_scope import (
    extract_all_file_scopes,
    extract_scopes_for_file,
    extract_scope,
    ASTScope,
    FileScope,
    detect_language,
    get_parser,
    get_language,
)

__all__ = [
    "parse_diff",
    "merge_adjacent_ranges",
    "DiffRange",
    "ParsedDiff",
    "get_ranges_for_file",
    "extract_all_file_scopes",
    "extract_scopes_for_file",
    "extract_scope",
    "ASTScope",
    "FileScope",
    "detect_language",
    "get_parser",
    "get_language",
]