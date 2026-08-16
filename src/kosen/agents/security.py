from __future__ import annotations
from typing import Optional
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI

from kosen.config import settings
from kosen.schemas import (
    CandidateFinding,
    FindingCategory,
    FindingSeverity,
    SourceLocation,
    ASTScope,
    ReviewState,
)


def get_llm() -> ChatOpenAI:
    """Create LLM client for NVIDIA API."""
    return ChatOpenAI(
        model=settings.nvidia_llm_model,
        base_url=settings.nvidia_base_url,
        api_key=settings.nvidia_api_key,
        temperature=0.1,
        max_tokens=4096,
        timeout=30,
        max_retries=2,
    )


SECURITY_SYSTEM_PROMPT = """You are a security code reviewer. Analyze the provided code scope for security vulnerabilities.

Focus on:
- SQL Injection (user input in raw queries)
- Command Injection (user input in shell commands)
- Path Traversal (user input in file paths)
- XSS (unescaped user input in HTML/JS)
- Secrets (hardcoded API keys, passwords, tokens)
- Insecure Deserialization (pickle, yaml.load, etc.)
- Authentication/Authorization bypasses
- Cryptographic issues (weak algorithms, hardcoded keys)

Output a JSON list of CandidateFinding objects with these fields:
- id: unique identifier (use "sec-{n}")
- category: "security"
- severity: "critical" | "high" | "medium" | "low" | "info"
- title: brief vulnerability title
- description: detailed explanation
- location: {file_path, start_line, end_line, start_column, end_column}
- snippet: the vulnerable code snippet
- suggested_fix: code fix suggestion (optional)
- confidence: 0.0-1.0
- reasoning: why this is a vulnerability

Only output findings you are confident about. If no issues, return empty list [].

Output ONLY the JSON array, no extra text or reasoning."""


def security_agent(state: ReviewState) -> dict:
    """Generate security candidates from AST scopes."""
    llm = get_llm()
    candidates: list[CandidateFinding] = []

    for file_scope in state.file_scopes:
        for scope in file_scope.scopes:
            # Build prompt with code context
            prompt = f"""Analyze this code for security vulnerabilities. Output ONLY a JSON array.

File: {file_scope.file_path}
Scope: {scope.node_type} {scope.node_name or ''}
Lines {scope.start_line}-{scope.end_line}

Code:
{scope.source_text}

Changed lines: {[f"{r.start_line}-{r.end_line} ({r.change_type})" if hasattr(r, 'start_line') else f"{r[0]}-{r[1]}" for r in file_scope.diff_ranges]}"""

            try:
                response = llm.invoke([
                    SystemMessage(content=SECURITY_SYSTEM_PROMPT),
                    HumanMessage(content=prompt)
                ])

                # Parse JSON response - extract from markdown code blocks or find last valid JSON array
                import json
                import re
                content = response.content.strip()
                
                # Try to extract from markdown code blocks (```json or ```)
                # Strategy: find all ```json blocks, take the last one
                json_blocks = list(re.finditer(r'```json\n(.*?)\n\s*```', content, re.DOTALL))
                if json_blocks:
                    content = json_blocks[-1].group(1).strip()
                else:
                    # Fallback: find ``` (no language) blocks with JSON
                    generic_blocks = list(re.finditer(r'```\n(.*?)\n\s*```', content, re.DOTALL))
                    for block in reversed(generic_blocks):
                        candidate = block.group(1).strip()
                        if candidate.startswith('[') and '{' in candidate:
                            content = candidate
                            break
                    else:
                        # Final fallback: if content starts with [, use it directly
                        if content.startswith('['):
                            pass  # content already good
                        else:
                            # Find all JSON arrays, pick last one with objects
                            all_arrays = list(re.finditer(r'\[.*?\]', content, re.DOTALL))
                            valid_arrays = [m for m in all_arrays if '{' in m.group()]
                            if valid_arrays:
                                content = valid_arrays[-1].group()
                            else:
                                content = re.sub(r'^```[a-zA-Z]*\n', '', content)
                                content = re.sub(r'\n```$', '', content)
                                content = content.strip()
                
                findings_data = json.loads(content)
                if isinstance(findings_data, list):
                    for i, f in enumerate(findings_data):
                        candidates.append(CandidateFinding(
                            id=f.get("id", f"sec-{len(candidates)}"),
                            category=FindingCategory.SECURITY,
                            severity=FindingSeverity(f.get("severity", "medium")),
                            title=f.get("title", "Security Issue"),
                            description=f.get("description", ""),
                            location=SourceLocation(
                                file_path=file_scope.file_path,
                                start_line=f.get("location", {}).get("start_line", scope.start_line),
                                end_line=f.get("location", {}).get("end_line", scope.end_line),
                                start_column=f.get("location", {}).get("start_column", 1),
                                end_column=f.get("location", {}).get("end_column", 1),
                            ),
                            snippet=f.get("snippet", scope.source_text[:200]),
                            suggested_fix=f.get("suggested_fix"),
                            confidence=f.get("confidence", 0.8),
                            reasoning=f.get("reasoning", ""),
                        ))
            except Exception as e:
                state.errors.append(f"Security agent error for {file_scope.file_path}:{scope.start_line}: {e}")

    return {"security_candidates": candidates}