"""GitHub integration for Kosen."""
from __future__ import annotations

import os
from typing import Optional

from github import Github
from github.PullRequest import PullRequest

from kosen.graph.workflow import run_review_sync
from kosen.parser.diff_parser import parse_diff


def get_pr_diff(pr: PullRequest) -> str:
    """Get unified diff for a PR."""
    return pr.get_diff()


def get_pr_files(pr: PullRequest) -> dict[str, str]:
    """Get source files (after state) for a PR."""
    files = {}
    for file in pr.get_files():
        if file.status != "removed" and file.patch:
            try:
                content = pr.base.repo.get_contents(file.filename, ref=pr.head.sha)
                files[file.filename] = content.decoded_content.decode("utf-8")
            except Exception:
                pass
    return files


def review_pr(
    repo_name: str,
    pr_number: int,
    token: str,
    post_comment: bool = True,
    base_branch: Optional[str] = None,
) -> dict:
    """Review a GitHub PR."""
    gh = Github(token)
    repo = gh.get_repo(repo_name)
    pr = repo.get_pull(pr_number)
    
    diff_text = get_pr_diff(pr)
    source_files = get_pr_files(pr)
    
    state = run_review_sync(diff_text=diff_text, source_files=source_files)
    
    result = {
        "pr": pr_number,
        "repo": repo_name,
        "verified_findings": [
            {
                "id": vf.candidate.id,
                "category": vf.candidate.category.value,
                "severity": vf.candidate.severity.value,
                "title": vf.candidate.title,
                "description": vf.candidate.description,
                "location": {
                    "file": vf.candidate.location.file_path,
                    "start_line": vf.candidate.location.start_line,
                    "end_line": vf.candidate.location.end_line,
                },
                "verification_status": vf.verification_status.value,
                "verification_tool": vf.verification_tool,
                "false_positive_risk": vf.false_positive_risk,
            }
            for vf in state.verified_findings
        ],
        "errors": state.errors,
        "summary": getattr(state, "_summary", ""),
        "pr_comment": getattr(state, "_pr_comment", ""),
    }
    
    if post_comment and getattr(state, "_pr_comment", None):
        try:
            pr.create_issue_comment(state._pr_comment)
            result["comment_posted"] = True
        except Exception as e:
            result["comment_error"] = str(e)
    
    return result


def format_pr_comment(state) -> str:
    """Format review state as PR comment (alias)."""
    return getattr(state, "_pr_comment", "No findings")