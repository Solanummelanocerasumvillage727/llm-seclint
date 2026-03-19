"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Configuration for a scan run."""

    include_patterns: list[str] = Field(default_factory=lambda: ["*.py"])
    exclude_patterns: list[str] = Field(default_factory=list)
    ignore_rules: list[str] = Field(default_factory=list)
    min_severity: str = ""
    output_format: str = "text"
    output_file: str = ""

    model_config = {"extra": "ignore"}


def load_config(config_path: Path | None = None) -> ScanConfig:
    """Load configuration from a YAML file.

    Searches for .llm-seclint.yml in the current directory and parent
    directories if no explicit path is given.

    Args:
        config_path: Explicit path to a config file, or None to auto-discover.

    Returns:
        Parsed and validated ScanConfig.
    """
    if config_path is not None:
        return _parse_config_file(config_path)

    # Auto-discover config file
    search_dir = Path.cwd()
    for directory in [search_dir, *search_dir.parents]:
        candidate = directory / ".llm-seclint.yml"
        if candidate.is_file():
            return _parse_config_file(candidate)
        candidate = directory / ".llm-seclint.yaml"
        if candidate.is_file():
            return _parse_config_file(candidate)

    return ScanConfig()


def _parse_config_file(path: Path) -> ScanConfig:
    """Parse a YAML config file into a ScanConfig."""
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, yaml.YAMLError) as exc:
        raise SystemExit(f"Error reading config file {path}: {exc}") from exc

    if not isinstance(data, dict):
        return ScanConfig()

    return ScanConfig(**data)
