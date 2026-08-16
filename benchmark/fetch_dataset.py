from __future__ import annotations
import json
import os
import hashlib
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import requests

from kosen.schemas import BenchmarkVulnerability
from kosen.parser.diff_parser import parse_diff, merge_adjacent_ranges


OSV_API_BASE = "https://api.osv.dev/v1"


@dataclass
class OSVQueryResult:
    """Result from OSV.dev vulnerability query."""
    vulns: list[dict]


class OSVClient:
    """Client for OSV.dev API."""
    
    def __init__(self, base_url: str = OSV_API_BASE, timeout: int = 30):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
    
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type(requests.RequestException),
        reraise=True
    )
    def query_vulnerabilities(
        self,
        package: str,
        ecosystem: str = "PyPI",
        version: Optional[str] = None
    ) -> list[dict]:
        """Query OSV for vulnerabilities affecting a package."""
        payload = {
            "package": {"name": package, "ecosystem": ecosystem}
        }
        if version:
            payload["version"] = version
        
        response = self.session.post(
            f"{self.base_url}/query",
            json=payload,
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json().get("vulns", [])
    
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type(requests.RequestException),
        reraise=True
    )
    def get_vulnerability(self, vuln_id: str) -> dict:
        """Get full vulnerability details by ID."""
        response = self.session.get(
            f"{self.base_url}/vulns/{vuln_id}",
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()


def extract_github_commit_urls(vuln: dict) -> list[str]:
    """Extract GitHub commit URLs from vulnerability references."""
    urls = []
    for ref in vuln.get("references", []):
        url = ref.get("url", "")
        if "github.com" in url and "/commit/" in url:
            urls.append(url)
    return urls


def parse_github_commit_url(url: str) -> Optional[tuple[str, str, str]]:
    """Parse GitHub commit URL to extract owner, repo, and commit SHA."""
    # https://github.com/owner/repo/commit/sha
    import re
    match = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]{7,40})", url)
    if match:
        return match.group(1), match.group(2), match.group(3)
    return None


def fetch_file_at_commit(owner: str, repo: str, path: str, commit_sha: str) -> Optional[str]:
    """Fetch file content from GitHub at a specific commit."""
    # Use raw.githubusercontent.com
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_sha}/{path}"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return None


def fetch_patch_from_commit(owner: str, repo: str, commit_sha: str) -> Optional[str]:
    """Fetch patch/diff from GitHub commit."""
    url = f"https://github.com/{owner}/{repo}/commit/{commit_sha}.patch"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return None


def compute_bug_line_ranges(patch_diff: str) -> list[tuple[int, int]]:
    """
    Compute ground-truth bug line ranges from patch diff.
    
    Parses the diff and extracts deleted/modified lines in the PRE-patch file
    as the bug location ground truth.
    """
    try:
        parsed = parse_diff(patch_diff)
        # Merge adjacent ranges
        merged = merge_adjacent_ranges(parsed.ranges)
        
        # Filter to removed/modified lines (these are the bug lines in pre-patch file)
        bug_ranges = []
        for r in merged:
            if r.change_type in ("removed", "modified"):
                bug_ranges.append((r.start_line, r.end_line))
        
        return bug_ranges
    except Exception:
        return []


def create_benchmark_vulnerability(
    osv_vuln: dict,
    file_before_path: str,
    file_before_content: str,
    patch_diff: str
) -> BenchmarkVulnerability:
    """Create a BenchmarkVulnerability from OSV data and fetched files."""
    bug_ranges = compute_bug_line_ranges(patch_diff)
    
    return BenchmarkVulnerability(
        osv_id=osv_vuln.get("id", ""),
        cve_id=next((a for a in osv_vuln.get("aliases", []) if a.startswith("CVE-")), None),
        summary=osv_vuln.get("summary", ""),
        affected_package=osv_vuln.get("affected", [{}])[0].get("package", {}).get("name", ""),
        fixed_versions=[
            r.get("fixed", "") 
            for affected in osv_vuln.get("affected", [])
            for r in affected.get("ranges", [])
            if r.get("type") == "ECOSYSTEM"
        ],
        file_before_path=file_before_path,
        file_before_content=file_before_content,
        patch_diff=patch_diff,
        bug_line_ranges=bug_ranges,
    )


def fetch_vulnerability_dataset(
    max_vulns: int = 100,
    dataset_dir: str = "benchmark/dataset",
    target_packages: Optional[list[str]] = None
) -> list[BenchmarkVulnerability]:
    """
    Fetch benchmark dataset from OSV.dev.
    
    Queries OSV for Python vulnerabilities with GitHub commits,
    downloads pre-patch files and patches, computes bug line ranges.
    """
    client = OSVClient()
    dataset_path = Path(dataset_dir)
    dataset_path.mkdir(parents=True, exist_ok=True)
    
    # Default target packages (popular Python packages with known vulns)
    if target_packages is None:
        target_packages = [
            "requests", "urllib3", "certifi", "charset-normalizer",
            "idna", "pillow", "numpy", "pandas", "django", "flask",
            "fastapi", "sqlalchemy", "redis", "celery", "pymongo",
            "paramiko", "cryptography", "pyjwt", "itsdangerous",
            "markupsafe", "jinja2", "werkzeug", "click", "boto3",
            "google-auth", "oauthlib", "pyopenssl", "service-identity",
        ]
    
    vulnerabilities: list[BenchmarkVulnerability] = []
    
    for package in target_packages:
        if len(vulnerabilities) >= max_vulns:
            break
        
        try:
            print(f"Querying {package}...")
            vulns = client.query_vulnerabilities(package)
            
            for vuln in vulns:
                if len(vulnerabilities) >= max_vulns:
                    break
                
                # Check if vuln has GitHub commit references
                commit_urls = extract_github_commit_urls(vuln)
                if not commit_urls:
                    continue
                
                # Try each commit URL
                for commit_url in commit_urls:
                    parsed = parse_github_commit_url(commit_url)
                    if not parsed:
                        continue
                    
                    owner, repo, commit_sha = parsed
                    
                    # Get the patch
                    patch_diff = fetch_patch_from_commit(owner, repo, commit_sha)
                    if not patch_diff:
                        continue
                    
                    # Parse patch to find modified files
                    try:
                        parsed_diff = parse_diff(patch_diff)
                    except Exception:
                        continue
                    
                    # For each modified Python file, try to get pre-patch version
                    for patched_file in parsed_diff.files_changed:
                        if not patched_file.endswith(".py"):
                            continue
                        
                        # Get file at parent commit (pre-patch)
                        parent_sha = commit_sha + "^"  # First parent
                        file_before = fetch_file_at_commit(owner, repo, patched_file, parent_sha)
                        if not file_before:
                            continue
                        
                        # Create benchmark vulnerability
                        bench_vuln = create_benchmark_vulnerability(
                            vuln, patched_file, file_before, patch_diff
                        )
                        
                        if bench_vuln.bug_line_ranges:
                            vulnerabilities.append(bench_vuln)
                            
                            # Save individual fixture
                            fixture_path = dataset_path / f"{bench_vuln.osv_id}.json"
                            fixture_path.write_text(
                                json.dumps(asdict(bench_vuln), indent=2),
                                encoding="utf-8"
                            )
                        
                        break  # One file per vulnerability is enough
        
        except Exception as e:
            print(f"Error processing {package}: {e}")
            continue
    
    # Save summary
    summary_path = dataset_path / "summary.json"
    summary_path.write_text(
        json.dumps([asdict(v) for v in vulnerabilities], indent=2),
        encoding="utf-8"
    )
    
    print(f"Fetched {len(vulnerabilities)} vulnerabilities")
    return vulnerabilities


def load_benchmark_dataset(dataset_dir: str = "benchmark/dataset") -> list[BenchmarkVulnerability]:
    """Load benchmark vulnerabilities from local fixtures."""
    dataset_path = Path(dataset_dir)
    vulnerabilities: list[BenchmarkVulnerability] = []
    
    for fixture_file in dataset_path.glob("*.json"):
        if fixture_file.name == "summary.json":
            continue
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
            vulnerabilities.append(BenchmarkVulnerability(**data))
        except Exception:
            continue
    
    return vulnerabilities