from __future__ import annotations
from enum import Enum
from typing import Optional, Literal, Annotated
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from operator import add


class FindingCategory(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    SYNTAX = "syntax"
    COVERAGE = "coverage"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    UNGATED_ADVISORY = "ungated_advisory"
    REJECTED = "rejected"
    ERROR = "error"


class SourceLocation(BaseModel):
    """Source code location reference."""
    model_config = ConfigDict(frozen=True)

    file_path: str
    start_line: int
    end_line: int
    start_column: int = 1
    end_column: int = 1


class CandidateFinding(BaseModel):
    """LLM-generated candidate finding before static tool verification."""
    model_config = ConfigDict(frozen=True)

    id: str
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    location: SourceLocation
    snippet: str
    suggested_fix: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class VerifiedFinding(BaseModel):
    """Finding that passed static tool verification gate."""
    model_config = ConfigDict(frozen=True)

    candidate: CandidateFinding
    verification_status: VerificationStatus
    verification_tool: str
    verification_output: str
    verified_at: datetime = Field(default_factory=datetime.utcnow)
    false_positive_risk: float = Field(ge=0.0, le=1.0, default=0.0)


class ASTScope(BaseModel):
    """Enclosing AST node scope extracted from full source."""
    model_config = ConfigDict(frozen=True)

    node_type: str
    node_name: Optional[str]
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    source_text: str
    context_before: str = ""
    context_after: str = ""


class FileScope(BaseModel):
    """All AST scopes for a single file mapped to diff changes."""
    model_config = ConfigDict(frozen=True)

    file_path: str
    full_source: str
    language: str
    scopes: list[ASTScope]
    diff_ranges: list[tuple[int, int]]  # (start_line, end_line) from unidiff


def _merge_lists(existing: list, new: list) -> list:
    """Reducer for list fields in LangGraph state."""
    return existing + new


def _keep_first(existing, new):
    """Reducer that keeps the first non-None value."""
    if existing is not None:
        return existing
    return new


def _merge_errors(existing: list, new: list) -> list:
    """Reducer for errors list."""
    return existing + new


class ReviewState(BaseModel):
    """LangGraph state for the review workflow."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Input
    pr_number: Annotated[Optional[int], _keep_first] = None
    repo_owner: Annotated[Optional[str], _keep_first] = None
    repo_name: Annotated[Optional[str], _keep_first] = None
    base_sha: Annotated[Optional[str], _keep_first] = None
    head_sha: Annotated[Optional[str], _keep_first] = None
    diff_text: Annotated[str, _keep_first] = ""
    files_changed: Annotated[list[str], _merge_lists] = Field(default_factory=list)

    # Parsed data
    file_scopes: Annotated[list[FileScope], _merge_lists] = Field(default_factory=list)

    # Candidate findings from LLM agents
    security_candidates: Annotated[list[CandidateFinding], _merge_lists] = Field(default_factory=list)
    performance_candidates: Annotated[list[CandidateFinding], _merge_lists] = Field(default_factory=list)
    coverage_candidates: Annotated[list[CandidateFinding], _merge_lists] = Field(default_factory=list)

    # Verified findings after static gate
    verified_findings: Annotated[list[VerifiedFinding], _merge_lists] = Field(default_factory=list)

    # Metadata
    errors: Annotated[list[str], _merge_errors] = Field(default_factory=list)
    started_at: Annotated[datetime, _keep_first] = Field(default_factory=datetime.utcnow)
    completed_at: Annotated[Optional[datetime], _keep_first] = None


class BenchmarkVulnerability(BaseModel):
    """Ground truth vulnerability from OSV.dev benchmark."""
    model_config = ConfigDict(frozen=True)

    osv_id: str
    cve_id: Optional[str]
    summary: str
    affected_package: str
    fixed_versions: list[str]
    file_before_path: str
    file_before_content: str
    patch_diff: str
    bug_line_ranges: list[tuple[int, int]]  # Ground truth from unidiff deleted/modified lines


class BenchmarkResult(BaseModel):
    """Evaluation result for a single vulnerability."""
    model_config = ConfigDict(frozen=True)

    vulnerability: BenchmarkVulnerability
    flagged_findings: list[VerifiedFinding]
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0


class BenchmarkSummary(BaseModel):
    """Aggregate benchmark metrics."""
    model_config = ConfigDict(frozen=True)

    total_vulnerabilities: int
    total_true_positives: int
    total_false_positives: int
    total_false_negatives: int
    overall_precision: float
    overall_recall: float
    per_category: dict[str, dict[str, float]]