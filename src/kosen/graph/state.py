from __future__ import annotations
from typing import Optional, Literal, Annotated
from datetime import datetime
from langgraph.graph import StateGraph, START, END
from pydantic import ConfigDict

from kosen.schemas import ReviewState, VerifiedFinding, FileScope


# Re-export for convenience
__all__ = ["ReviewState", "VerifiedFinding", "FileScope"]


def create_initial_state(
    diff_text: str = "",
    files_changed: Optional[list[str]] = None,
    pr_number: Optional[int] = None,
    repo_owner: Optional[str] = None,
    repo_name: Optional[str] = None,
    base_sha: Optional[str] = None,
    head_sha: Optional[str] = None,
) -> ReviewState:
    """Create an initial review state."""
    return ReviewState(
        diff_text=diff_text,
        files_changed=files_changed or [],
        pr_number=pr_number,
        repo_owner=repo_owner,
        repo_name=repo_name,
        base_sha=base_sha,
        head_sha=head_sha,
    )