from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from kosen.config import settings, get_semgrep_cmd, get_ruff_cmd
from kosen.schemas import (
    CandidateFinding,
    VerifiedFinding,
    FindingCategory,
    VerificationStatus,
    ASTScope,
)


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying a candidate against a static tool."""
    candidate: CandidateFinding
    status: VerificationStatus
    tool: str
    output: str
    matches: list[dict] = field(default_factory=list)


class StaticGate:
    """
    Main verification gate that routes candidates to appropriate static tools.
    
    Security -> semgrep (security-audit, owasp-top-ten, secrets)
    Performance/Syntax -> ruff (B, SIM, E, F rules) + semgrep custom patterns
    Coverage -> diff-cover / AST branch analysis
    """
    
    def __init__(self, work_dir: Optional[Path] = None):
        self.work_dir = work_dir or Path(tempfile.gettempdir()) / "kosen_review"
        self.work_dir.mkdir(parents=True, exist_ok=True)
    
    def verify_candidates(
        self,
        candidates: list[CandidateFinding],
        file_scopes: list[ASTScope],
        source_files: dict[str, str]
    ) -> list[VerificationResult]:
        """Route candidates to appropriate verifiers and collect results."""
        results: list[VerificationResult] = []
        
        # Group by category
        security_candidates = [c for c in candidates if c.category == FindingCategory.SECURITY]
        perf_candidates = [c for c in candidates if c.category in (FindingCategory.PERFORMANCE, FindingCategory.SYNTAX)]
        coverage_candidates = [c for c in candidates if c.category == FindingCategory.COVERAGE]
        
        if security_candidates:
            results.extend(self._verify_security(security_candidates, source_files))
        
        if perf_candidates:
            results.extend(self._verify_performance_syntax(perf_candidates, source_files))
        
        if coverage_candidates:
            results.extend(self._verify_coverage(coverage_candidates, source_files))
        
        return results
    
    def _verify_security(
        self,
        candidates: list[CandidateFinding],
        source_files: dict[str, str]
    ) -> list[VerificationResult]:
        """Verify security candidates using semgrep with security rule packs."""
        results: list[VerificationResult] = []
        
        # Create temp files for each unique source file
        temp_files: dict[str, Path] = {}
        for file_path, source in source_files.items():
            temp_file = self.work_dir / Path(file_path).name
            temp_file.write_text(source, encoding="utf-8")
            temp_files[file_path] = temp_file
        
        # Run semgrep for each rule pack
        for rule_pack in settings.semgrep_security_rules:
            for file_path, temp_file in temp_files.items():
                try:
                    cmd = get_semgrep_cmd([rule_pack], str(temp_file))
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        cwd=self.work_dir,
                        shell=False  # Explicit shell=False for Windows
                    )
                    
                    semgrep_output = json.loads(result.stdout) if result.stdout else {"results": []}
                    matches = semgrep_output.get("results", [])
                    
                    # Match candidates to semgrep findings
                    for candidate in candidates:
                        if candidate.location.file_path != file_path:
                            continue
                        
                        candidate_matches = self._match_candidate_to_findings(
                            candidate, matches
                        )
                        
                        if candidate_matches:
                            results.append(VerificationResult(
                                candidate=candidate,
                                status=VerificationStatus.VERIFIED,
                                tool=f"semgrep:{rule_pack}",
                                output=json.dumps(candidate_matches, indent=2),
                                matches=candidate_matches,
                            ))
                        else:
                            results.append(VerificationResult(
                                candidate=candidate,
                                status=VerificationStatus.REJECTED,
                                tool=f"semgrep:{rule_pack}",
                                output="No matching semgrep finding for candidate location",
                                matches=[],
                            ))
                
                except subprocess.TimeoutExpired:
                    results.append(VerificationResult(
                        candidate=candidates[0],  # placeholder
                        status=VerificationStatus.ERROR,
                        tool=f"semgrep:{rule_pack}",
                        output="Semgrep timed out",
                        matches=[],
                    ))
                except json.JSONDecodeError:
                    results.append(VerificationResult(
                        candidate=candidates[0],
                        status=VerificationStatus.ERROR,
                        tool=f"semgrep:{rule_pack}",
                        output="Failed to parse semgrep JSON output",
                        matches=[],
                    ))
                except Exception as e:
                    results.append(VerificationResult(
                        candidate=candidates[0],
                        status=VerificationStatus.ERROR,
                        tool=f"semgrep:{rule_pack}",
                        output=str(e),
                        matches=[],
                    ))
        
        return results
    
    def _verify_performance_syntax(
        self,
        candidates: list[CandidateFinding],
        source_files: dict[str, str]
    ) -> list[VerificationResult]:
        """Verify performance/syntax candidates using ruff and semgrep perf rules."""
        results: list[VerificationResult] = []
        
        temp_files: dict[str, Path] = {}
        for file_path, source in source_files.items():
            temp_file = self.work_dir / Path(file_path).name
            temp_file.write_text(source, encoding="utf-8")
            temp_files[file_path] = temp_file
        
        # Run ruff with relevant rule codes
        # B = bugbear, SIM = simplify, E = pycodestyle, F = pyflakes
        ruff_select = ["B", "SIM", "E", "F", "UP", "PERF"]
        
        for file_path, temp_file in temp_files.items():
            try:
                cmd = get_ruff_cmd(str(temp_file), select=ruff_select)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=self.work_dir,
                    shell=False  # Explicit shell=False for Windows
                )
                
                ruff_output = json.loads(result.stdout) if result.stdout else []
                
                for candidate in candidates:
                    if candidate.location.file_path != file_path:
                        continue
                    
                    candidate_matches = self._match_candidate_to_ruff(candidate, ruff_output)
                    
                    if candidate_matches:
                        results.append(VerificationResult(
                            candidate=candidate,
                            status=VerificationStatus.VERIFIED,
                            tool="ruff",
                            output=json.dumps(candidate_matches, indent=2),
                            matches=candidate_matches,
                        ))
                    else:
                        # Also try semgrep performance rules as fallback
                        semgrep_results = self._run_semgrep_perf(file_path, temp_file, candidate)
                        results.extend(semgrep_results)
            
            except Exception as e:
                results.append(VerificationResult(
                    candidate=candidates[0] if candidates else None,
                    status=VerificationStatus.ERROR,
                    tool="ruff",
                    output=str(e),
                    matches=[],
                ))
        
        return results
    
    def _run_semgrep_perf(
        self,
        file_path: str,
        temp_file: Path,
        candidate: CandidateFinding
    ) -> list[VerificationResult]:
        """Run semgrep performance rules as fallback for performance candidates."""
        results: list[VerificationResult] = []
        
        for rule_pack in settings.semgrep_perf_rules:
            try:
                cmd = get_semgrep_cmd([rule_pack], str(temp_file))
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=self.work_dir,
                    shell=False  # Explicit shell=False for Windows
                )
                
                semgrep_output = json.loads(result.stdout) if result.stdout else {"results": []}
                matches = semgrep_output.get("results", [])
                
                candidate_matches = self._match_candidate_to_findings(candidate, matches)
                
                if candidate_matches:
                    results.append(VerificationResult(
                        candidate=candidate,
                        status=VerificationStatus.VERIFIED,
                        tool=f"semgrep:{rule_pack}",
                        output=json.dumps(candidate_matches, indent=2),
                        matches=candidate_matches,
                    ))
                else:
                    results.append(VerificationResult(
                        candidate=candidate,
                        status=VerificationStatus.REJECTED,
                        tool=f"semgrep:{rule_pack}",
                        output="No matching semgrep performance finding",
                        matches=[],
                    ))
            
            except Exception as e:
                results.append(VerificationResult(
                    candidate=candidate,
                    status=VerificationStatus.ERROR,
                    tool=f"semgrep:{rule_pack}",
                    output=str(e),
                    matches=[],
                ))
        
        return results
    
    def _verify_coverage(
        self,
        candidates: list[CandidateFinding],
        source_files: dict[str, str]
    ) -> list[VerificationResult]:
        """Verify coverage candidates using diff-cover / AST branch analysis."""
        results: list[VerificationResult] = []
        
        # For coverage, we typically need test runner output + diff-cover
        # This is a simplified implementation - marks as UNGATED_ADVISORY
        # since we don't have the test execution environment here
        
        for candidate in candidates:
            results.append(VerificationResult(
                candidate=candidate,
                status=VerificationStatus.UNGATED_ADVISORY,
                tool="diff-cover",
                output="Coverage verification requires test execution environment. Marked as ungated advisory.",
                matches=[],
            ))
        
        return results
    
    def _match_candidate_to_findings(
        self,
        candidate: CandidateFinding,
        findings: list[dict]
    ) -> list[dict]:
        """Match a candidate finding to static tool findings by location."""
        matches: list[dict] = []
        cand_start = max(1, candidate.location.start_line or 1)
        cand_end = max(cand_start, candidate.location.end_line or cand_start)
        cand_file = candidate.location.file_path
        cand_file_norm = cand_file.replace("\\", "/").lower()
        
        for finding in findings:
            # semgrep finding structure: {"path": "...", "start": {"line": N}, "end": {"line": M}}
            find_path = finding.get("path", "")
            find_path_norm = find_path.replace("\\", "/").lower()
            find_start = max(1, finding.get("start", {}).get("line", 0) or 1)
            find_end = max(find_start, finding.get("end", {}).get("line", 0) or find_start)
            
            # Check if finding overlaps with candidate location
            if (find_path_norm.endswith(cand_file_norm) or cand_file_norm.endswith(find_path_norm)) and not (
                find_end < cand_start or find_start > cand_end
            ):
                matches.append(finding)
        
        return matches
    
    def _match_candidate_to_ruff(
        self,
        candidate: CandidateFinding,
        ruff_findings: list[dict]
    ) -> list[dict]:
        """Match candidate to ruff findings."""
        matches: list[dict] = []
        cand_start = max(1, candidate.location.start_line or 1)
        cand_end = max(cand_start, candidate.location.end_line or cand_start)
        cand_file = candidate.location.file_path
        cand_file_norm = cand_file.replace("\\", "/").lower()
        
        for finding in ruff_findings:
            # ruff finding: {"filename": "...", "location": {"row": N, "column": M}, "end_location": {...}}
            find_file = finding.get("filename", "")
            find_file_norm = find_file.replace("\\", "/").lower()
            find_start = max(1, finding.get("location", {}).get("row", 0) or 1)
            find_end = max(find_start, finding.get("end_location", {}).get("row", find_start) or find_start)
            
            if (find_file_norm.endswith(cand_file_norm) or cand_file_norm.endswith(find_file_norm)) and not (
                find_end < cand_start or find_start > cand_end
            ):
                matches.append(finding)
        
        return matches


def convert_to_verified_findings(results: list[VerificationResult]) -> list[VerifiedFinding]:
    """Convert verification results to VerifiedFinding objects."""
    verified: list[VerifiedFinding] = []
    
    for result in results:
        if result.candidate is None:
            continue
        
        # Calculate false positive risk based on verification status
        if result.status == VerificationStatus.VERIFIED:
            fp_risk = 0.1  # Low risk for tool-verified findings
        elif result.status == VerificationStatus.UNGATED_ADVISORY:
            fp_risk = 0.5  # Medium risk for un-gated
        else:
            fp_risk = 0.9  # High risk for rejected/error
        
        verified.append(VerifiedFinding(
            candidate=result.candidate,
            verification_status=result.status,
            verification_tool=result.tool,
            verification_output=result.output,
            false_positive_risk=fp_risk,
        ))
    
    return verified