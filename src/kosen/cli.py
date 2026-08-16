#!/usr/bin/env python3
"""Kosen CLI - Production-grade code review."""
from __future__ import annotations

import sys
import json
import os
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv

# Load .env from user config dir, then package directory (global config), then CWD
# This allows global config without per-project .env files
user_config_dir = Path.home() / ".config" / "kosen"
load_dotenv(user_config_dir / ".env")
package_dir = Path(__file__).parent.parent
load_dotenv(package_dir / ".env")
load_dotenv()  # Also load from CWD (overrides global)

from kosen.graph.workflow import run_review_sync
from kosen.parser.diff_parser import parse_diff


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Kosen - Agentic Code Reviewer with AST-grounded static verification.

    Review local diffs or GitHub PRs. Finds security, performance, and coverage issues
    verified by static analysis tools (semgrep, ruff, diff-cover).

    Examples:
      kosen review changes.diff -s .              # Local review
      kosen review changes.patch -s . -f json     # JSON output
      kosen github -r owner/repo -p 123 --post    # Review GH PR
    """
    pass


@cli.command()
@click.argument("diff_file", type=click.Path(exists=True, path_type=Path))
@click.option("--source-dir", "-s", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".", help="Root directory for source files (auto-detects from diff)")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file (default: stdout)")
@click.option("--format", "-f", type=click.Choice(["markdown", "json", "summary"]), default="markdown", help="Output format: markdown (default), json, or summary")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed progress")
def review(diff_file: Path, source_dir: Path, output: Optional[Path], format: str, verbose: bool):
    """Review a unified diff file against source files.

    Generates a diff with 'git diff' or 'git diff main..feature', then runs
    security, performance, and coverage analysis with static verification.

    Example:
      git diff main > changes.diff
      kosen review changes.diff -s . -f markdown
    """
    
    # Handle BOM and encoding issues
    try:
        diff_text = diff_file.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        diff_text = diff_file.read_text(encoding="latin-1")
    
    # Auto-detect source files from diff
    parsed = parse_diff(diff_text)
    source_files = {}
    for file_path in parsed.files_changed:
        full_path = source_dir / file_path
        if full_path.exists():
            try:
                source_files[file_path] = full_path.read_text(encoding="utf-8-sig")
            except UnicodeDecodeError:
                source_files[file_path] = full_path.read_text(encoding="latin-1")
        else:
            click.echo(f"Warning: {file_path} not found in {source_dir}", err=True)
    
    if verbose:
        click.echo(f"Reviewing {len(parsed.files_changed)} files...", err=True)
    
    state = run_review_sync(diff_text=diff_text, source_files=source_files)
    
    if format == "json":
        result = {
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
        }
        out = json.dumps(result, indent=2)
    elif format == "summary":
        out = getattr(state, "_summary", "No summary")
    else:  # markdown
        out = getattr(state, "_pr_comment", "No PR comment generated")
    
    if output:
        output.write_text(out, encoding="utf-8")
        click.echo(f"Written to {output}", err=True)
    else:
        click.echo(out)


@cli.command()
@click.option("--repo", "-r", required=True, help="Repository in format owner/name")
@click.option("--pr", "-p", required=True, type=int, help="PR number (e.g., 123)")
@click.option("--token", "-t", envvar="GITHUB_TOKEN", help="GitHub token (or set GITHUB_TOKEN env var)")
@click.option("--post/--no-post", default=True, help="Post comment to PR (default: --post)")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Also save output to file")
def github(repo: str, pr: int, token: str, post: bool, output: Optional[Path]):
    """Review a GitHub PR and optionally post comment.

    Fetches PR diff from GitHub API, runs full review pipeline,
    and posts results as a PR comment (with --post).

    Example:
      kosen github -r owner/repo -p 123 --post
      kosen github -r owner/repo -p 123 --no-post -o review.json
    """
    if not token:
        click.echo("Error: --token or GITHUB_TOKEN required", err=True)
        sys.exit(1)
    
    from kosen.github import review_pr
    click.echo(f"Reviewing PR #{pr} in {repo}...", err=True)
    
    result = review_pr(repo, pr, token, post_comment=post)
    
    out = json.dumps(result, indent=2)
    if output:
        output.write_text(out, encoding="utf-8")
        click.echo(f"Written to {output}", err=True)
    else:
        click.echo(out)


if __name__ == "__main__":
    cli()