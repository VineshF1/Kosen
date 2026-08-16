from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from unidiff import PatchSet
from unidiff.errors import UnidiffParseError


@dataclass(frozen=True)
class DiffRange:
    """A contiguous range of changed lines in a file."""
    file_path: str
    start_line: int
    end_line: int
    change_type: str  # 'added', 'removed', 'modified'
    source_before: Optional[str] = None  # File path for pre-change state
    source_after: Optional[str] = None   # File path for post-change state


@dataclass(frozen=True)
class ParsedDiff:
    """Result of parsing a unified diff."""
    ranges: list[DiffRange]
    files_changed: list[str]


def parse_diff(diff_text: str) -> ParsedDiff:
    """
    Parse a unified diff and extract changed line ranges per file.
    
    Uses unidiff to properly handle:
    - Context lines
    - Added/removed/modified line classification
    - Multi-file diffs
    - Binary files (skipped)
    """
    ranges: list[DiffRange] = []
    files_changed: list[str] = []

    try:
        patch_set = PatchSet(diff_text.encode() if isinstance(diff_text, str) else diff_text)
    except UnidiffParseError as e:
        raise ValueError(f"Failed to parse diff: {e}") from e

    for patched_file in patch_set:
        file_path = patched_file.path
        if patched_file.is_binary_file:
            continue

        files_changed.append(file_path)

        # Determine source file paths for pre/post states
        # For PR reviews: source_after = current file, source_before = base version
        # For bug analysis: source_before = file_before.py, source_after = patched
        source_before = patched_file.source_file if patched_file.source_file != "/dev/null" else None
        source_after = patched_file.target_file if patched_file.target_file != "/dev/null" else None

        for hunk in patched_file:
            # hunk.source_start: line number in source (pre-change) file
            # hunk.target_start: line number in target (post-change) file
            # hunk.source_length: number of lines in source
            # hunk.target_length: number of lines in target

            # Extract the actual changed lines from the hunk's line data
            # This gives us the precise line numbers that were added/removed/modified
            added_lines = []
            removed_lines = []
            modified_lines = []
            
            source_line = hunk.source_start
            target_line = hunk.target_start
            
            for line in hunk:
                if line.line_type == "+":
                    added_lines.append(target_line)
                    target_line += 1
                elif line.line_type == "-":
                    removed_lines.append(source_line)
                    source_line += 1
                else:  # context line
                    source_line += 1
                    target_line += 1
            
            # Classify and create ranges for actual changes
            if added_lines and not removed_lines:
                change_type = "added"
                start = min(added_lines)
                end = max(added_lines)
            elif removed_lines and not added_lines:
                change_type = "removed"
                start = min(removed_lines)
                end = max(removed_lines)
            else:
                change_type = "modified"
                # For modified, use the target line numbers (post-change)
                all_lines = added_lines + removed_lines
                start = min(all_lines) if all_lines else hunk.target_start
                end = max(all_lines) if all_lines else hunk.target_start + hunk.target_length - 1

            if start <= end:
                ranges.append(DiffRange(
                    file_path=file_path,
                    start_line=start,
                    end_line=end,
                    change_type=change_type,
                    source_before=source_before,
                    source_after=source_after,
                ))

    return ParsedDiff(ranges=ranges, files_changed=files_changed)


def merge_adjacent_ranges(ranges: list[DiffRange], max_gap: int = 3) -> list[DiffRange]:
    """Merge adjacent or nearby ranges of the same file and type."""
    if not ranges:
        return []

    # Sort by file, then start_line
    sorted_ranges = sorted(ranges, key=lambda r: (r.file_path, r.start_line))
    merged: list[DiffRange] = [sorted_ranges[0]]

    for current in sorted_ranges[1:]:
        last = merged[-1]
        if (current.file_path == last.file_path
                and current.change_type == last.change_type
                and current.start_line <= last.end_line + max_gap + 1):
            # Merge: extend the end_line
            merged[-1] = DiffRange(
                file_path=last.file_path,
                start_line=last.start_line,
                end_line=max(last.end_line, current.end_line),
                change_type=last.change_type,
                source_before=last.source_before,
                source_after=last.source_after,
            )
        else:
            merged.append(current)

    return merged


def get_ranges_for_file(parsed: ParsedDiff, file_path: str) -> list[DiffRange]:
    """Get all diff ranges for a specific file."""
    return [r for r in parsed.ranges if r.file_path == file_path]