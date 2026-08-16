from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from kosen.schemas import CandidateFinding, FindingCategory


@dataclass(frozen=True)
class CoverageMatch:
    """A coverage gap finding."""
    file_path: str
    missing_branches: list[tuple[int, int]]  # (start_line, end_line) of uncovered branches
    missing_lines: list[int]
    branch_coverage: float
    line_coverage: float


class CoverageVerifier:
    """
    Test coverage verifier using diff-cover and AST branch analysis.
    
    This is a simplified implementation. In production, you would:
    1. Run test suite with coverage (pytest --cov)
    2. Run diff-cover with coverage.xml and diff
    3. Parse diff-cover output for uncovered branches/lines in changed code
    
    For now, marks all coverage candidates as UNGATED_ADVISORY since
    we don't have the test execution environment.
    """
    
    def __init__(
        self,
        work_dir: Optional[Path] = None,
        timeout: int = 120
    ):
        self.work_dir = work_dir or Path(tempfile.gettempdir()) / "kosen_coverage"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
    
    def verify(
        self,
        candidates: list[CandidateFinding],
        source_files: dict[str, str],
        coverage_xml: Optional[str] = None,
        diff_text: Optional[str] = None
    ) -> list[CoverageMatch]:
        """
        Verify coverage candidates.
        
        Args:
            candidates: Coverage category candidates
            source_files: Source code files
            coverage_xml: Path to coverage.xml from test run (optional)
            diff_text: Unified diff text (optional)
        
        Returns:
            List of coverage matches (empty if no test environment)
        """
        coverage_candidates = [
            c for c in candidates 
            if c.category == FindingCategory.COVERAGE
        ]
        if not coverage_candidates:
            return []
        
        # If we have coverage data and diff, run diff-cover
        if coverage_xml and diff_text:
            return self._run_diff_cover(coverage_xml, diff_text, coverage_candidates)
        
        # Otherwise, return empty (will be marked as UNGATED_ADVISORY by static gate)
        return []
    
    def _run_diff_cover(
        self,
        coverage_xml: str,
        diff_text: str,
        candidates: list[CandidateFinding]
    ) -> list[CoverageMatch]:
        """Run diff-cover to find uncovered branches in changed code."""
        matches: list[CoverageMatch] = []
        
        try:
            # Write diff to temp file
            diff_file = self.work_dir / "changes.diff"
            diff_file.write_text(diff_text, encoding="utf-8")
            
            # Run diff-cover
            cmd = [
                "diff-cover",
                coverage_xml,
                "--compare-branch=HEAD",
                "--diff-file", str(diff_file),
                "--json-report", str(self.work_dir / "diff_cover_report.json")
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.work_dir
            )
            
            # Parse diff-cover JSON report
            report_file = self.work_dir / "diff_cover_report.json"
            if report_file.exists():
                with open(report_file) as f:
                    report = json.load(f)
                
                matches = self._parse_diff_cover_report(report, candidates)
        
        except Exception:
            pass  # Return empty matches on any error
        
        return matches
    
    def _parse_diff_cover_report(
        self,
        report: dict,
        candidates: list[CandidateFinding]
    ) -> list[CoverageMatch]:
        """Parse diff-cover JSON report for uncovered branches."""
        matches: list[CoverageMatch] = []
        
        # diff-cover report structure varies, but typically has:
        # {"files": {"file.py": {"violations": [...], "coverage": {...}}}}
        files_data = report.get("files", {})
        
        for file_path, file_data in files_data.items():
            # Find candidates for this file
            file_candidates = [c for c in candidates if c.location.file_path.endswith(file_path)]
            if not file_candidates:
                continue
            
            violations = file_data.get("violations", [])
            if not violations:
                continue
            
            # Extract missing branches/lines
            missing_branches: list[tuple[int, int]] = []
            missing_lines: list[int] = []
            
            for viol in violations:
                # violation: {"line": N, "type": "branch"/"line", ...}
                if viol.get("type") == "branch":
                    line = viol.get("line", 0)
                    missing_branches.append((line, line))
                else:
                    missing_lines.append(viol.get("line", 0))
            
            if missing_branches or missing_lines:
                coverage = file_data.get("coverage", {})
                matches.append(CoverageMatch(
                    file_path=file_path,
                    missing_branches=missing_branches,
                    missing_lines=missing_lines,
                    branch_coverage=coverage.get("branch", 0.0),
                    line_coverage=coverage.get("line", 0.0),
                ))
        
        return matches
    
    def analyze_ast_branches(self, source: str, file_path: str) -> list[tuple[int, int]]:
        """
        Analyze AST for branch points (if/elif/else, for/while/else, try/except/finally, etc.)
        
        Returns line ranges of branches that could be uncovered.
        This is a static analysis fallback when no coverage data is available.
        """
        # This would use tree-sitter to find branch nodes
        # Simplified for now - returns empty
        return []