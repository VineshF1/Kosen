# Kosen — Complete Setup & Usage Guide

## Overview

Kosen is an agentic code reviewer with three interfaces:
- **CLI** — Local review of any diff file
- **GitHub Action** — Automatic PR reviews on every push
- **`kosen github`** — Ad-hoc PR review from terminal

---

## 1. Initial Installation (One-time)

```bash
# Clone and install
git clone https://github.com/your-org/kosen.git
cd kosen
pip install -e .
pip install semgrep ruff diff-cover
```

This installs the `kosen` command globally.

---

## 2. Configure Credentials (One-time)

### Option A: User Config (Recommended for CLI)

```bash
# Create user config directory
mkdir -p ~/.config/kosen

# Add your NVIDIA API key
echo "NVIDIA_API_KEY=your_key_here" > ~/.config/kosen/.env

# Optional: GitHub token for `kosen github` command
echo "GITHUB_TOKEN=ghp_your_token_here" >> ~/.config/kosen/.env
```

**Locations:**
- **Windows**: `C:\Users\<username>\.config\kosen\.env`
- **Linux/macOS**: `~/.config/kosen/.env`

### Option B: Environment Variables (Alternative)

```bash
# Windows (PowerShell)
[Environment]::SetEnvironmentVariable("NVIDIA_API_KEY", "your_key", "User")

# Linux/macOS (add to ~/.bashrc or ~/.zshrc)
export NVIDIA_API_KEY=your_key
```

---

## 3. Local Review (CLI)

### Basic Usage

```bash
# In any project directory
cd /path/to/your/project

# Generate diff of your changes
# Windows PowerShell (avoids UTF-16):
git diff --no-color main | Out-File -Encoding utf8 changes.diff
# Or simple (may have encoding issues on Windows):
git diff main > changes.diff
# Linux/macOS / Git Bash:
git diff --no-color main > changes.diff


# Review with Kosen
kosen review changes.diff -s . -f markdown
```

### Options

| Flag | Description |
|------|-------------|
| `-s, --source-dir` | Source root (default: `.`) |
| `-f, --format` | `markdown` \| `json` \| `summary` |
| `-o, --output` | Save to file |
| `-v, --verbose` | Show progress |

### Examples

```bash
# JSON output for CI
kosen review changes.diff -s . -f json -o review.json

# Summary only
kosen review changes.diff -s . -f summary

# Compare branches
git diff main..feature > changes.diff
kosen review changes.diff -s .
```

---

## 4. GitHub Action Setup (Automatic PR Reviews)

### Step 1: Copy Action to Target Repo

```bash
# In the repo where you want reviews
mkdir -p .github/actions
cp -r /path/to/kosen/.github/actions/kosen-review/ .github/actions/
```

### Step 2: Create Workflow File

Create `.github/workflows/code-review.yml`:

```yaml
name: Kosen Code Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/kosen-review
        with:
          nvidia-api-key: ${{ secrets.NVIDIA_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Step 3: Add Secret in GitHub

Go to **Repo Settings → Secrets and variables → Actions → New repository secret**:

| Name | Value |
|------|-------|
| `NVIDIA_API_KEY` | Your NVIDIA API key |

**That's it.** `GITHUB_TOKEN` is provided automatically by GitHub.

### Optional: Customize

```yaml
- uses: ./.github/actions/kosen-review
  with:
    nvidia-api-key: ${{ secrets.NVIDIA_API_KEY }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    model: "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning"
    rules: "security,performance,coverage"
    fail-on-critical: "true"
```

---

## 5. Ad-hoc PR Review (CLI)

```bash
# Review a specific PR (requires GITHUB_TOKEN in ~/.config/kosen/.env or env var)
kosen github -r owner/repo -p 123 --post

# Options
kosen github -r owner/repo -p 123 --no-post -o review.json
```

| Flag | Description |
|------|-------------|
| `-r, --repo` | Repository (owner/name) |
| `-p, --pr` | PR number |
| `-t, --token` | GitHub token (or `GITHUB_TOKEN` env) |
| `--post/--no-post` | Post comment to PR |
| `-o, --output` | Save JSON to file |

---

## 6. How It Works

```
Diff → Parse (unidiff) → Extract scopes (tree-sitter)
         ↓
Parallel LLM Agents:
  • Security (SQLi, XSS, secrets, auth, crypto)
  • Performance (leaks, complexity, N+1, exceptions)
  • Coverage (untested branches, edge cases, error paths)
         ↓
Static Verification Gate:
  • semgrep (security-audit, OWASP, secrets)
  • ruff (B, SIM, PERF, bugbear)
  • diff-cover (coverage gaps)
         ↓
Only VERIFIED findings → Markdown/JSON/PR Comment
```

---

## 7. Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError` | `pip install -e .` from Kosen directory |
| `NVIDIA_API_KEY not set` | Add to `~/.config/kosen/.env` |
| `semgrep not found` | `pip install semgrep` |
| LLM timeout | Increase `timeout` in `get_llm()` (default 30s) |
| No findings | Use `git diff --no-color > changes.diff` |
| Bad credentials (401) | Check `GITHUB_TOKEN` has `repo` scope |
| UTF-16 diff (Windows) | Use `git diff --no-color \| Out-File -Encoding utf8 changes.diff` |

---

## 8. Development

```bash
# Run tests
python -m pytest tests/ -v

# Format
ruff format src/

# Lint
ruff check src/
```

---

## 9. File Structure

```
kosen/
├── .github/actions/kosen-review/   # GitHub Action (copy to target repos)
├── src/kosen/
│   ├── cli.py          # CLI (review, github)
│   ├── github.py       # PyGithub PR integration
│   ├── config.py       # Settings (loads ~/.config/kosen/.env)
│   ├── parser/         # Diff + AST parsing
│   ├── agents/         # Security, Performance, Coverage
│   ├── verification/   # Static gate (semgrep, ruff, diff-cover)
│   ├── graph/          # LangGraph workflow
│   └── benchmark/      # OSV.dev evaluation
├── tests/              # Core unit tests
├── README.md
└── RUN.md
```

---

## Quick Reference

```bash
# One-time setup
mkdir -p ~/.config/kosen
echo "NVIDIA_API_KEY=***" > ~/.config/kosen/.env

# Local review

# Windows PowerShell:
git diff --no-color main | Out-File -Encoding utf8 changes.diff
# Or simple (may have encoding issues on Windows):
git diff main > changes.diff
# Linux/macOS / Git Bash:
git diff --no-color main > changes.diff

# Review with Kosen
kosen review changes.diff -s . -f markdown

# GitHub Action: copy .github/actions/kosen-review/ + add NVIDIA_API_KEY secret

# Ad-hoc PR review
kosen github -r owner/repo -p 123 --post
```