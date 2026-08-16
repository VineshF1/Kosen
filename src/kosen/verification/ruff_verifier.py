from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from kosen.config import settings, get_ruff_cmd
from kosen.schemas import CandidateFinding, FindingCategory


@dataclass(frozen=True)
class RuffMatch:
    """A single ruff finding matched to a candidate."""
    code: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    fix: Optional[dict] = None


class RuffVerifier:
    """
    Syntax and performance-focused ruff verifier.
    
    Runs ruff with rule codes:
    - B = flake8-bugbear (bugs, design issues)
    - SIM = flake8-simplify (simplifiable code)
    - E = pycodestyle (style)
    - F = pyflakes (logic errors)
    - UP = pyupgrade (modern syntax)
    - PERF = perflint (performance)
    """
    
    def __init__(
        self,
        select: Optional[list[str]] = None,
        work_dir: Optional[Path] = None,
        timeout: int = 60
    ):
        self.select = select or ["B", "SIM", "E", "F", "UP", "PERF"]
        self.work_dir = work_dir or Path(tempfile.gettempdir()) / "kosen_ruff"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
    
    def verify(
        self,
        candidates: list[CandidateFinding],
        source_files: dict[str, str]
    ) -> list[RuffMatch]:
        """Run ruff on source files and return matches for candidates."""
        if not candidates:
            return []
        
        # Filter to performance/syntax candidates
        perf_candidates = [
            c for c in candidates 
            if c.category in (FindingCategory.PERFORMANCE, FindingCategory.SYNTAX)
        ]
        if not perf_candidates:
            return []
        
        temp_files = self._write_temp_files(source_files)
        all_matches: list[RuffMatch] = []
        
        for file_path, temp_file in temp_files.items():
            matches = self._run_ruff(temp_file, file_path)
            all_matches.extend(matches)
        
        return self._filter_matches_to_candidates(all_matches, perf_candidates)
    
    def _write_temp_files(self, source_files: dict[str, str]) -> dict[str, Path]:
        """Write source files to temp directory."""
        temp_files: dict[str, Path] = {}
        for file_path, source in source_files.items():
            safe_name = Path(file_path).name
            base = self.work_dir / safe_name
            if base.exists():
                import hashlib
                h = hashlib.md5(file_path.encode()).hexdigest()[:8]
                stem = Path(safe_name).stem
                suffix = Path(safe_name).suffix
                safe_name = f"{stem}_{h}{suffix}"
                base = self.work_dir / safe_name
            
            base.write_text(source, encoding="utf-8")
            temp_files[file_path] = base
        return temp_files
    
    def _run_ruff(self, target_file: Path, original_path: str) -> list[RuffMatch]:
        """Run ruff on a single file."""
        cmd = get_ruff_cmd(str(target_file), select=self.select)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.work_dir
            )
        except subprocess.TimeoutExpired:
            return []
        except Exception:
            return []
        
        # Ruff returns 0 for no issues, 1 for issues found
        if result.returncode not in (0, 1):
            return []
        
        try:
            findings = json.loads(result.stdout) if result.stdout else []
        except json.JSONDecodeError:
            return []
        
        matches: list[RuffMatch] = []
        for finding in findings:
            matches.append(RuffMatch(
                code=finding.get("code", ""),
                message=finding.get("message", ""),
                file_path=original_path,
                start_line=finding.get("location", {}).get("row", 0),
                end_line=finding.get("end_location", {}).get("row", 0),
                start_col=finding.get("location", {}).get("column", 0),
                end_col=finding.get("end_location", {}).get("column", 0),
                fix=finding.get("fix"),
            ))
        
        return matches
    
    def _filter_matches_to_candidates(
        self,
        matches: list[RuffMatch],
        candidates: list[CandidateFinding]
    ) -> list[RuffMatch]:
        """Keep only matches that overlap with candidate locations."""
        if not candidates:
            return []
        
        filtered: list[RuffMatch] = []
        for match in matches:
            for candidate in candidates:
                if self._overlaps(match, candidate):
                    filtered.append(match)
                    break
        return filtered
    
    def _overlaps(self, match: RuffMatch, candidate: CandidateFinding) -> bool:
        """Check if a ruff match overlaps with a candidate location."""
        cand_file = candidate.location.file_path
        match_file = match.file_path
        
        # Normalize paths for cross-platform comparison
        cand_file_norm = cand_file.replace("\\", "/").lower()
        match_file_norm = match_file.replace("\\", "/").lower()
        if not (cand_file_norm.endswith(match_file_norm) or match_file_norm.endswith(cand_file_norm)):
            return False
        
        cand_start = max(1, candidate.location.start_line or 1)
        cand_end = max(cand_start, candidate.location.end_line or cand_start)
        match_start = max(1, match.start_line or 1)
        match_end = max(match_start, match.end_line or match_start)
        
        return not (match_end < cand_start or match_start > cand_end)
    
    def verify_all_rules(self, source_files: dict[str, str]) -> list[RuffMatch]:
        """Run all ruff rules on all files, return all findings."""
        temp_files = self._write_temp_files(source_files)
        all_matches: list[RuffMatch] = []
        
        for file_path, temp_file in temp_files.items():
            matches = self._run_ruff(temp_file, file_path)
            all_matches.extend(matches)
        
        return all_matches