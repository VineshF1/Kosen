from __future__ import annotations
from typing import Optional
from langgraph.graph import StateGraph, START, END

from kosen.schemas import ReviewState
from kosen.parser.diff_parser import parse_diff, merge_adjacent_ranges
from kosen.parser.ast_scope import extract_all_file_scopes, detect_language
from kosen.verification import StaticGate, convert_to_verified_findings
from kosen.agents import security_agent, performance_agent, coverage_agent
from kosen.graph.explainer import format_pr_comment, format_summary


def parse_diff_node(state: ReviewState) -> dict:
    """Parse the diff and extract changed line ranges."""
    diff_text = state.diff_text
    if not diff_text:
        return {"errors": ["No diff text provided"]}

    try:
        parsed = parse_diff(diff_text)
        # Merge adjacent ranges for cleaner scope extraction
        merged_ranges = merge_adjacent_ranges(parsed.ranges)
        return {
            "files_changed": parsed.files_changed,
            "_merged_diff_ranges": merged_ranges,
        }
    except Exception as e:
        return {"errors": [f"Diff parsing failed: {e}"]}


def extract_scopes_node(state: ReviewState) -> dict:
    """Extract AST scopes for changed files."""
    merged_ranges = state.__dict__.get("_merged_diff_ranges", [])
    if not merged_ranges:
        return {"errors": ["No diff ranges to extract scopes for"]}

    # Get source files from injected dict
    source_files = state.__dict__.get("_source_files", {})
    if not source_files:
        return {"errors": ["No source files provided for scope extraction"]}

    try:
        file_scopes = extract_all_file_scopes(
            merged_ranges,
            source_files,
            context_lines=5
        )
        return {"file_scopes": file_scopes}
    except Exception as e:
        return {"errors": [f"Scope extraction failed: {e}"]}


def security_candidates_node(state: ReviewState) -> dict:
    """Generate security candidates."""
    return security_agent(state)


def performance_candidates_node(state: ReviewState) -> dict:
    """Generate performance/syntax candidates."""
    return performance_agent(state)


def coverage_candidates_node(state: ReviewState) -> dict:
    """Generate coverage candidates."""
    return coverage_agent(state)


def verification_gate_node(state: ReviewState) -> dict:
    """Run static tool verification on all candidates."""
    all_candidates = (
        state.security_candidates +
        state.performance_candidates +
        state.coverage_candidates
    )

    if not all_candidates:
        return {"verified_findings": []}

    # Collect source files from file_scopes
    source_files = {}
    for fs in state.file_scopes:
        source_files[fs.file_path] = fs.full_source

    try:
        gate = StaticGate()
        results = gate.verify_candidates(all_candidates, [], source_files)
        return {"verified_findings": convert_to_verified_findings(results)}
    except Exception as e:
        return {"errors": [f"Verification gate failed: {e}"]}


def format_output_node(state: ReviewState) -> dict:
    """Format final output."""
    from datetime import datetime
    return {
        "completed_at": datetime.utcnow(),
        "_pr_comment": format_pr_comment(state.verified_findings),
        "_summary": format_summary(state.verified_findings),
    }


def build_workflow() -> StateGraph:
    """Build the LangGraph workflow DAG - sequential execution to avoid state issues."""
    
    # Define the graph
    workflow = StateGraph(ReviewState)
    
    # Add nodes
    workflow.add_node("parse_diff", parse_diff_node)
    workflow.add_node("extract_scopes", extract_scopes_node)
    workflow.add_node("security_candidates", security_candidates_node)
    workflow.add_node("performance_candidates", performance_candidates_node)
    workflow.add_node("coverage_candidates", coverage_candidates_node)
    workflow.add_node("verification_gate", verification_gate_node)
    workflow.add_node("format_output", format_output_node)
    
    # Sequential execution
    workflow.add_edge(START, "parse_diff")
    workflow.add_edge("parse_diff", "extract_scopes")
    workflow.add_edge("extract_scopes", "security_candidates")
    workflow.add_edge("security_candidates", "performance_candidates")
    workflow.add_edge("performance_candidates", "coverage_candidates")
    workflow.add_edge("coverage_candidates", "verification_gate")
    workflow.add_edge("verification_gate", "format_output")
    workflow.add_edge("format_output", END)
    
    return workflow


def compile_workflow() -> StateGraph:
    """Compile the workflow for execution."""
    workflow = build_workflow()
    return workflow.compile()


async def run_review(
    diff_text: str,
    source_files: dict[str, str],
    pr_number: Optional[int] = None,
    repo_owner: Optional[str] = None,
    repo_name: Optional[str] = None,
    base_sha: Optional[str] = None,
    head_sha: Optional[str] = None,
) -> ReviewState:
    """
    Run the complete code review workflow.
    
    Args:
        diff_text: Unified diff text
        source_files: Dict mapping file_path -> full source content
        pr_number: PR number (optional)
        repo_owner: Repository owner (optional)
        repo_name: Repository name (optional)
        base_sha: Base commit SHA (optional)
        head_sha: Head commit SHA (optional)
    
    Returns:
        Final ReviewState with verified findings and formatted output
    """
    app = compile_workflow()
    
    initial_state = ReviewState(
        diff_text=diff_text,
        files_changed=list(source_files.keys()),
        pr_number=pr_number,
        repo_owner=repo_owner,
        repo_name=repo_name,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    
    # Inject source files for scope extraction
    initial_state.__dict__["_source_files"] = source_files
    
    # Run the workflow
    final_state = await app.ainvoke(initial_state)
    
    return final_state


def run_review_sync(
    diff_text: str,
    source_files: dict[str, str],
    pr_number: Optional[int] = None,
    repo_owner: Optional[str] = None,
    repo_name: Optional[str] = None,
    base_sha: Optional[str] = None,
    head_sha: Optional[str] = None,
) -> ReviewState:
    """Synchronous version of run_review - runs pipeline sequentially without LangGraph."""
    from datetime import datetime
    
    state = ReviewState(
        diff_text=diff_text,
        files_changed=list(source_files.keys()),
        pr_number=pr_number,
        repo_owner=repo_owner,
        repo_name=repo_name,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    
    # Inject source files for scope extraction
    state.__dict__["_source_files"] = source_files
    
    # Step 1: Parse diff
    print("Step 1: Parsing diff...")
    parse_result = parse_diff_node(state)
    for k, v in parse_result.items():
        if k == "errors":
            state.errors.extend(v)
        else:
            setattr(state, k, v)
    if state.errors:
        print(f"  Errors: {state.errors}")
    
    # Step 2: Extract scopes
    print("Step 2: Extracting scopes...")
    scope_result = extract_scopes_node(state)
    for k, v in scope_result.items():
        if k == "errors":
            state.errors.extend(v)
        else:
            setattr(state, k, v)
    if state.errors:
        print(f"  Errors: {state.errors}")
    
    # Step 3: Security candidates
    print("Step 3: Security analysis...")
    sec_result = security_candidates_node(state)
    for k, v in sec_result.items():
        if k == "errors":
            state.errors.extend(v)
        else:
            existing = getattr(state, k, [])
            setattr(state, k, existing + v)
    
    # Step 4: Performance candidates
    print("Step 4: Performance analysis...")
    perf_result = performance_candidates_node(state)
    for k, v in perf_result.items():
        if k == "errors":
            state.errors.extend(v)
        else:
            existing = getattr(state, k, [])
            setattr(state, k, existing + v)
    
    # Step 5: Coverage candidates
    print("Step 5: Coverage analysis...")
    cov_result = coverage_candidates_node(state)
    for k, v in cov_result.items():
        if k == "errors":
            state.errors.extend(v)
        else:
            existing = getattr(state, k, [])
            setattr(state, k, existing + v)
    
    # Step 6: Verification gate
    print("Step 6: Verification gate...")
    verify_result = verification_gate_node(state)
    for k, v in verify_result.items():
        if k == "errors":
            state.errors.extend(v)
        else:
            existing = getattr(state, k, [])
            setattr(state, k, existing + v)
    
    # Step 7: Format output
    print("Step 7: Formatting output...")
    format_result = format_output_node(state)
    for k, v in format_result.items():
        setattr(state, k, v)
    
    state.completed_at = datetime.utcnow()
    
    return state