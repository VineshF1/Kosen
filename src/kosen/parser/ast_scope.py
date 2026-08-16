from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import tree_sitter
from tree_sitter import Language, Parser, Node, Tree

from .diff_parser import DiffRange


@dataclass(frozen=True)
class ASTScope:
    """Enclosing AST node scope extracted from full source."""
    node_type: str
    node_name: Optional[str]
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    source_text: str
    context_before: str = ""
    context_after: str = ""


@dataclass(frozen=True)
class FileScope:
    """All AST scopes for a single file mapped to diff changes."""
    file_path: str
    full_source: str
    language: str
    scopes: list[ASTScope]
    diff_ranges: list[DiffRange]


# Tree-sitter language cache
_LANGUAGE_CACHE: dict[str, Language] = {}
_PARSER_CACHE: dict[str, Parser] = {}


def get_language(lang_name: str) -> Language:
    """Get or load a tree-sitter language."""
    if lang_name not in _LANGUAGE_CACHE:
        try:
            # Try to load from tree-sitter-python package
            if lang_name == "python":
                import tree_sitter_python
                _LANGUAGE_CACHE[lang_name] = Language(tree_sitter_python.language())
            else:
                raise ValueError(f"Unsupported language: {lang_name}")
        except Exception as e:
            raise RuntimeError(f"Failed to load tree-sitter language '{lang_name}': {e}") from e
    return _LANGUAGE_CACHE[lang_name]


def get_parser(lang_name: str) -> Parser:
    """Get or create a parser for the language."""
    if lang_name not in _PARSER_CACHE:
        parser = Parser()
        parser.language = get_language(lang_name)
        _PARSER_CACHE[lang_name] = parser
    return _PARSER_CACHE[lang_name]


def detect_language(file_path: str) -> str:
    """Detect language from file extension."""
    ext = Path(file_path).suffix.lower()
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".c": "c",
        ".h": "c",
        ".hpp": "cpp",
        ".rs": "rust",
        ".go": "go",
    }
    return lang_map.get(ext, "python")


def extract_node_name(node: Node, source: bytes) -> Optional[str]:
    """Extract a human-readable name from an AST node."""
    # Try common name fields
    for field_name in ["name", "identifier", "function_name", "class_name", "method_name"]:
        child = node.child_by_field_name(field_name)
        if child:
            return source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
    
    # For function/class definitions, look for first child that's an identifier
    if node.type in ("function_definition", "class_definition", "method_definition"):
        for child in node.children:
            if child.type == "identifier":
                return source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
    
    return None


def find_enclosing_node(root: Node, target_line: int, target_column: int = 1) -> Optional[Node]:
    """
    Find the smallest enclosing AST node that contains the target position.
    
    Args:
        root: Root node of the AST
        target_line: 1-indexed line number
        target_column: 1-indexed column number
    
    Returns:
        The enclosing node, or None if not found
    """
    target_point = tree_sitter.Point(target_line - 1, target_column - 1)
    
    def traverse(node: Node) -> Optional[Node]:
        # Check if target is within this node's range
        if node.start_point <= target_point <= node.end_point:
            # Recurse into children to find the most specific enclosing node
            for child in node.children:
                result = traverse(child)
                if result:
                    return result
            return node
        return None
    
    return traverse(root)


def extract_scope(
    source: str,
    diff_range: DiffRange,
    language: str = "python",
    context_lines: int = 5
) -> ASTScope:
    """
    Extract the enclosing AST scope for a diff range.
    
    Maps the changed line range to the immediate enclosing AST parent node
    (function, class, or execution block) and extracts its full text with context.
    """
    parser = get_parser(language)
    tree = parser.parse(source.encode())
    root = tree.root_node
    
    # Find the enclosing node for the start of the diff range
    # Use the start of the first changed line
    enclosing = find_enclosing_node(root, diff_range.start_line, 1)
    
    if enclosing is None:
        # Fallback: use the whole file
        enclosing = root
    
    # Extract source text for the node
    node_text = source[enclosing.start_byte:enclosing.end_byte]
    
    # Extract context before/after
    lines = source.splitlines(keepends=True)
    start_idx = max(0, enclosing.start_point[0] - context_lines)
    end_idx = min(len(lines), enclosing.end_point[0] + 1 + context_lines)
    
    context_before = "".join(lines[start_idx:enclosing.start_point[0]])
    context_after = "".join(lines[enclosing.end_point[0] + 1:end_idx])
    
    node_name = extract_node_name(enclosing, source.encode())
    
    return ASTScope(
        node_type=enclosing.type,
        node_name=node_name,
        start_line=enclosing.start_point[0] + 1,
        end_line=enclosing.end_point[0] + 1,
        start_column=enclosing.start_point[1] + 1,
        end_column=enclosing.end_point[1] + 1,
        source_text=node_text,
        context_before=context_before,
        context_after=context_after,
    )


def extract_scopes_for_file(
    file_path: str,
    source: str,
    diff_ranges: list[DiffRange],
    language: Optional[str] = None,
    context_lines: int = 5
) -> FileScope:
    """
    Extract all AST scopes for a file that correspond to diff changes.
    
    For each diff range, finds the enclosing AST node and extracts its scope.
    Deduplicates overlapping scopes (e.g., multiple changes in same function).
    """
    if language is None:
        language = detect_language(file_path)
    
    scopes: list[ASTScope] = []
    seen_nodes: set[tuple[int, int]] = set()  # (start_line, end_line) of node
    
    for diff_range in diff_ranges:
        scope = extract_scope(source, diff_range, language, context_lines)
        
        # Deduplicate by node boundaries
        node_key = (scope.start_line, scope.end_line)
        if node_key not in seen_nodes:
            seen_nodes.add(node_key)
            scopes.append(scope)
    
    # Sort by start line
    scopes.sort(key=lambda s: s.start_line)
    
    return FileScope(
        file_path=file_path,
        full_source=source,
        language=language,
        scopes=scopes,
        diff_ranges=diff_ranges,
    )


def extract_all_file_scopes(
    diff_ranges: list[DiffRange],
    file_sources: dict[str, str],
    context_lines: int = 5
) -> list[FileScope]:
    """
    Extract AST scopes for all files in a diff.
    
    Args:
        diff_ranges: Parsed diff ranges from parse_diff()
        file_sources: Mapping of file_path -> full source text
        context_lines: Lines of context around each AST node
    
    Returns:
        List of FileScope objects, one per changed file
    """
    from .diff_parser import get_ranges_for_file
    
    # Group ranges by file
    files = set(r.file_path for r in diff_ranges)
    result: list[FileScope] = []
    
    for file_path in files:
        source = file_sources.get(file_path)
        if source is None:
            continue  # Skip files we don't have source for
        
        file_ranges = get_ranges_for_file(
            type('ParsedDiff', (), {'ranges': diff_ranges})(), file_path
        )
        
        file_scope = extract_scopes_for_file(
            file_path, source, file_ranges, context_lines=context_lines
        )
        result.append(file_scope)
    
    return result