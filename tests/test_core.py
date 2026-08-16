import pytest
from kosen.parser.diff_parser import parse_diff, merge_adjacent_ranges, DiffRange
from kosen.parser.ast_scope import extract_scope, ASTScope, detect_language
from kosen.schemas import (
    CandidateFinding,
    VerifiedFinding,
    ReviewState,
    FindingCategory,
    FindingSeverity,
    VerificationStatus,
    SourceLocation,
)


SAMPLE_DIFF = """--- a/example.py
+++ b/example.py
@@ -1,5 +1,5 @@
 def process_data(data):
     result = []
     for item in data:
-        result.append(item * 2)
+        result.append(item ** 2)
     return result
"""


def test_parse_diff():
    """Test parsing a simple diff."""
    parsed = parse_diff(SAMPLE_DIFF)
    
    assert len(parsed.ranges) == 1
    assert parsed.files_changed == ["example.py"]
    
    range_obj = parsed.ranges[0]
    assert range_obj.file_path == "example.py"
    assert range_obj.start_line == 4
    assert range_obj.end_line == 4
    assert range_obj.change_type == "modified"


def test_merge_adjacent_ranges():
    """Test merging adjacent diff ranges."""
    ranges = [
        DiffRange("test.py", 10, 12, "modified"),
        DiffRange("test.py", 13, 15, "modified"),
        DiffRange("test.py", 20, 22, "added"),
    ]
    
    merged = merge_adjacent_ranges(ranges, max_gap=2)
    
    assert len(merged) == 2
    assert merged[0].start_line == 10
    assert merged[0].end_line == 15
    assert merged[1].start_line == 20
    assert merged[1].end_line == 22


def test_detect_language():
    """Test language detection from file extension."""
    assert detect_language("test.py") == "python"
    assert detect_language("test.js") == "javascript"
    assert detect_language("test.ts") == "typescript"
    assert detect_language("test.java") == "java"
    assert detect_language("test.unknown") == "python"  # default


def test_candidate_finding_creation():
    """Test creating a CandidateFinding."""
    finding = CandidateFinding(
        id="sec-1",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        title="SQL Injection",
        description="User input directly in query",
        location=SourceLocation(
            file_path="test.py",
            start_line=10,
            end_line=10,
        ),
        snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        confidence=0.9,
        reasoning="Direct string interpolation in SQL query",
    )
    
    assert finding.id == "sec-1"
    assert finding.category == FindingCategory.SECURITY
    assert finding.severity == FindingSeverity.HIGH
    assert finding.confidence == 0.9


def test_verified_finding_creation():
    """Test creating a VerifiedFinding."""
    from datetime import datetime
    
    candidate = CandidateFinding(
        id="sec-1",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.HIGH,
        title="SQL Injection",
        description="User input directly in query",
        location=SourceLocation(file_path="test.py", start_line=10, end_line=10),
        snippet="...",
        confidence=0.9,
        reasoning="...",
    )
    
    verified = VerifiedFinding(
        candidate=candidate,
        verification_status=VerificationStatus.VERIFIED,
        verification_tool="semgrep:p/security-audit",
        verification_output="Found SQL injection",
        false_positive_risk=0.1,
    )
    
    assert verified.verification_status == VerificationStatus.VERIFIED
    assert verified.false_positive_risk == 0.1


def test_review_state():
    """Test ReviewState creation."""
    state = ReviewState(
        diff_text=SAMPLE_DIFF,
        files_changed=["example.py"],
        pr_number=42,
        repo_owner="test",
        repo_name="repo",
    )
    
    assert state.diff_text == SAMPLE_DIFF
    assert state.files_changed == ["example.py"]
    assert state.pr_number == 42


if __name__ == "__main__":
    pytest.main([__file__, "-v"])