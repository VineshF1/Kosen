from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from kosen.config import settings, get_semgrep_cmd
from kosen.schemas import CandidateFinding, FindingCategory


@dataclass(frozen=True)
class SemgrepMatch:
    """A single semgrep finding matched to a candidate."""
    rule_id: str
    message: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    match_text: str


class SemgrepVerifier:
    """
    Security-focused semgrep verifier.
    
    Runs semgrep with security rule packs:
    - p/security-audit
    - p/owasp-top-ten  
    - p/secrets
    - Custom performance rules
    """
    
    def __init__(
        self,
        rule_packs: Optional[list[str]] = None,
        work_dir: Optional[Path] = None,
        timeout: int = 60
    ):
        self.rule_packs = rule_packs or settings.semgrep_security_rules
        self.work_dir = work_dir or Path(tempfile.gettempdir()) / "kosen_semgrep"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
    
    def verify(
        self,
        candidates: list[CandidateFinding],
        source_files: dict[str, str]
    ) -> list[SemgrepMatch]:
        """
        Run semgrep on source files and return matches for candidates.
        
        Returns only findings that overlap with candidate locations.
        """
        if not candidates:
            return []
        
        # Filter to security candidates
        security_candidates = [
            c for c in candidates 
            if c.category == FindingCategory.SECURITY
        ]
        if not security_candidates:
            return []
        
        # Create temp files
        temp_files = self._write_temp_files(source_files)
        
        all_matches: list[SemgrepMatch] = []
        
        for rule_pack in self.rule_packs:
            for file_path, temp_file in temp_files.items():
                matches = self._run_semgrep(rule_pack, temp_file, file_path)
                all_matches.extend(matches)
        
        # Filter matches to only those overlapping with candidates
        return self._filter_matches_to_candidates(all_matches, security_candidates)
    
    def _write_temp_files(self, source_files: dict[str, str]) -> dict[str, Path]:
        """Write source files to temp directory."""
        temp_files: dict[str, Path] = {}
        for file_path, source in source_files.items():
            # Use a safe filename
            safe_name = Path(file_path).name
            # Handle potential collisions
            base = self.work_dir / safe_name
            if base.exists():
                # Add hash to avoid collision
                import hashlib
                h = hashlib.md5(file_path.encode()).hexdigest()[:8]
                stem = Path(safe_name).stem
                suffix = Path(safe_name).suffix
                safe_name = f"{stem}_{h}{suffix}"
                base = self.work_dir / safe_name
            
            base.write_text(source, encoding="utf-8")
            temp_files[file_path] = base
        return temp_files
    
    def _run_semgrep(
        self,
        rule_pack: str,
        target_file: Path,
        original_path: str
    ) -> list[SemgrepMatch]:
        """Run semgrep on a single file with a rule pack."""
        cmd = get_semgrep_cmd([rule_pack], str(target_file))
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.work_dir,
                shell=False  # Explicit shell=False for Windows
            )
        except subprocess.TimeoutExpired:
            return []
        except Exception:
            return []
        
        if result.returncode not in (0, 1):  # 0 = no findings, 1 = findings found
            return []
        
        try:
            output = json.loads(result.stdout) if result.stdout else {"results": []}
        except json.JSONDecodeError:
            return []
        
        matches: list[SemgrepMatch] = []
        for finding in output.get("results", []):
            matches.append(SemgrepMatch(
                rule_id=finding.get("check_id", ""),
                message=finding.get("extra", {}).get("message", ""),
                severity=finding.get("extra", {}).get("severity", "UNKNOWN"),
                file_path=original_path,
                start_line=finding.get("start", {}).get("line", 0),
                end_line=finding.get("end", {}).get("line", 0),
                start_col=finding.get("start", {}).get("col", 0),
                end_col=finding.get("end", {}).get("col", 0),
                match_text=finding.get("extra", {}).get("lines", ""),
            ))
        
        return matches
    
    def _filter_matches_to_candidates(
        self,
        matches: list[SemgrepMatch],
        candidates: list[CandidateFinding]
    ) -> list[SemgrepMatch]:
        """Keep only matches that overlap with candidate locations."""
        if not candidates:
            return []
        
        filtered: list[SemgrepMatch] = []
        for match in matches:
            for candidate in candidates:
                if self._overlaps(match, candidate):
                    filtered.append(match)
                    break
        return filtered
    
    def _overlaps(self, match: SemgrepMatch, candidate: CandidateFinding) -> bool:
        """Check if a semgrep match overlaps with a candidate location."""
        # File path match (handle relative/absolute differences)
        cand_file = candidate.location.file_path
        match_file = match.file_path
        
        # Normalize paths for cross-platform comparison
        cand_file_norm = cand_file.replace("\\", "/").lower()
        match_file_norm = match_file.replace("\\", "/").lower()
        if not (cand_file_norm.endswith(match_file_norm) or match_file_norm.endswith(cand_file_norm)):
            return False
        
        # Line range overlap with safe defaults
        cand_start = max(1, candidate.location.start_line or 1)
        cand_end = max(cand_start, candidate.location.end_line or cand_start)
        match_start = max(1, match.start_line or 1)
        match_end = max(match_start, match.end_line or match_start)
        
        return not (match_end < cand_start or match_start > cand_end)
    
    def verify_all_rules(self, source_files: dict[str, str]) -> list[SemgrepMatch]:
        """Run all semgrep rules on all files, return all findings (no candidate filtering)."""
        temp_files = self._write_temp_files(source_files)
        all_matches: list[SemgrepMatch] = []
        
        for rule_pack in self.rule_packs:
            for file_path, temp_file in temp_files.items():
                matches = self._run_semgrep(rule_pack, temp_file, file_path)
                all_matches.extend(matches)
        
        return all_matches