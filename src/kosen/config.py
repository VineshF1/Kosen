import os
from pathlib import Path
from typing import Optional, ClassVar
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # Load from user config dir, then package dir, then CWD
    user_config: ClassVar[Path] = Path.home() / ".config" / "kosen" / ".env"
    package_dir: ClassVar[Path] = Path(__file__).parent.parent
    model_config = SettingsConfigDict(
        env_file=[user_config, package_dir / ".env", ".env"],
        env_file_encoding="utf-8",
        extra="ignore",
    )
    # NVIDIA API
    nvidia_api_key: str = Field(default="", validation_alias="NVIDIA_API_KEY")
    nvidia_base_url: str = Field(
        default="https://integrate.api.nvidia.com/v1",
        validation_alias="NVIDIA_BASE_URL"
    )
    nvidia_llm_model: str = Field(
        default="nvidia/nemotron-3.5-lightning-30b-a3b",
        validation_alias="NVIDIA_LLM_MODEL"
    )

    # GitHub API
    github_token: str = Field(default="", validation_alias="GITHUB_TOKEN")

    # OSV.dev API
    osv_api_base_url: str = Field(
        default="https://api.osv.dev/v1",
        validation_alias="OSV_API_BASE_URL"
    )

    # Static analysis tools paths
    semgrep_path: str = Field(default="semgrep", validation_alias="SEMGREP_PATH")
    ruff_path: str = Field(default="ruff", validation_alias="RUFF_PATH")
    diff_cover_path: str = Field(default="diff-cover", validation_alias="DIFF_COVER_PATH")

    # Semgrep rule packs
    semgrep_security_rules: list[str] = Field(
        default=["p/security-audit", "p/owasp-top-ten", "p/secrets"],
        validation_alias="SEMGREP_SECURITY_RULES"
    )
    semgrep_perf_rules: list[str] = Field(
        default=["p/python", "p/performance"],
        validation_alias="SEMGREP_PERF_RULES"
    )

    # Tree-sitter language pack
    tree_sitter_python_path: str = Field(
        default="",
        validation_alias="TREE_SITTER_PYTHON_PATH"
    )

    # Benchmark settings
    benchmark_dataset_dir: str = Field(
        default="benchmark/dataset",
        validation_alias="BENCHMARK_DATASET_DIR"
    )
    benchmark_max_vulns: int = Field(
        default=100,
        validation_alias="BENCHMARK_MAX_VULNS"
    )


settings = Settings()


def get_semgrep_cmd(rules: list[str], target: str, config: Optional[str] = None) -> list[str]:
    """Build semgrep command for given rules."""
    cmd = [settings.semgrep_path, "scan", "--json", "--quiet"]
    for rule in rules:
        cmd.extend(["--config", rule])
    if config:
        cmd.extend(["--config", config])
    cmd.append(target)
    return cmd


def get_ruff_cmd(target: str, select: Optional[list[str]] = None) -> list[str]:
    """Build ruff command."""
    cmd = [settings.ruff_path, "check", "--output-format=json"]
    if select:
        cmd.extend(["--select", ",".join(select)])
    cmd.append(target)
    return cmd