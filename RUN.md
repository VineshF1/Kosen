# RUN.md — Kosen Agentic Code Reviewer

## Quick Start

```bash
# 1. Install
cd Kosen
pip install -e .
pip install semgrep ruff diff-cover

# 2. Configure (one-time)
cp .env.example .env
# Edit .env and add your NVIDIA_API_KEY
# Get key from: https://build.nvidia.com/

# 3. Review local changes
# Windows PowerShell (avoids UTF-16):
git diff --no-color main | Out-File -Encoding utf8 changes.diff
# Or simple (may have encoding issues on Windows):
git diff main > changes.diff
# Linux/macOS / Git Bash:
git diff --no-color main > changes.diff

# Review with Kosen
kosen review changes.diff -s . -f markdown
```

---

## Commands

| Command | What it does |
|---------|--------------|
| `kosen review file.diff -s .` | Review a local diff file |
| `kosen review file.diff -s . -f json` | Output as JSON |
| `kosen review file.diff -s . -o out.md` | Save to file |
| `kosen github -r owner/repo -p 123` | Review a GitHub PR |

---

## GitHub Token Setup

```bash
# 1. Create token at: https://github.com/settings/tokens
#    Select: repo (full control)

# 2. Add to .env
echo "GITHUB_TOKEN=ghp_your_token_here" >> .env

# 3. For GitHub Action: add as repo secret in GitHub Settings
#    NVIDIA_API_KEY and GITHUB_TOKEN
```

---

## GitHub Action Setup

```bash
# 1. Copy action to your repo
cp -r .github/actions/kosen-review/ your-repo/.github/actions/

# 2. Create workflow file: .github/workflows/code-review.yml
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

# 3. Add NVIDIA_API_KEY to GitHub repo secrets
```

---

## Environment Variables

| Variable | Required | Where |
|----------|----------|-------|
| `NVIDIA_API_KEY` | Yes | `.env` |
| `NVIDIA_BASE_URL` | No | `.env` (default: https://integrate.api.nvidia.com/v1) |
| `NVIDIA_LLM_MODEL` | No | `.env` (default: nemotron-3-nano-omni-30b-a3b-reasoning) |
| `GITHUB_TOKEN` | For GitHub | `.env` or GitHub secrets |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Run `pip install -e .` from Kosen directory |
| `NVIDIA_API_KEY not set` | Add to `.env` file |
| `semgrep not found` | Run `pip install semgrep` |
| LLM timeout | Increase `timeout` in `get_llm()` (default 30s) |
| No findings found | Use `git diff --no-color > changes.diff` |
| Bad credentials (401) | Check GITHUB_TOKEN has `repo` scope |
| UnicodeDecodeError | Use `git diff --no-color` to avoid ANSI codes |

---

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Format code
ruff format src/

# Lint
ruff check src/
```