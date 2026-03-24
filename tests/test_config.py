"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from llm_seclint.config import ScanConfig, load_config


class TestScanConfig:
    """Tests for ScanConfig defaults."""

    def test_default_values(self) -> None:
        cfg = ScanConfig()

        assert cfg.include_patterns == ["*.py"]
        assert cfg.exclude_patterns == []
        assert cfg.ignore_rules == []
        assert cfg.min_severity == "HIGH"
        assert cfg.output_format == "text"
        assert cfg.output_file == ""


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_from_yaml(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text(
            "include_patterns:\n"
            "  - '*.py'\n"
            "  - '*.pyi'\n"
            "output_format: json\n"
        )

        cfg = load_config(cfg_file)

        assert cfg.include_patterns == ["*.py", "*.pyi"]
        assert cfg.output_format == "json"

    def test_config_with_ignore_rules(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text(
            "ignore_rules:\n"
            "  - LS001\n"
            "  - LS002\n"
        )

        cfg = load_config(cfg_file)
        assert cfg.ignore_rules == ["LS001", "LS002"]

    def test_config_with_min_severity(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text("min_severity: HIGH\n")

        cfg = load_config(cfg_file)
        assert cfg.min_severity == "HIGH"

    def test_config_with_include_exclude_patterns(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text(
            "include_patterns:\n"
            "  - '*.py'\n"
            "exclude_patterns:\n"
            "  - 'test_*.py'\n"
        )

        cfg = load_config(cfg_file)
        assert cfg.include_patterns == ["*.py"]
        assert cfg.exclude_patterns == ["test_*.py"]

    def test_malformed_yaml_returns_default(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        # YAML that parses to a string, not a dict
        cfg_file.write_text("just a plain string\n")

        cfg = load_config(cfg_file)
        assert cfg == ScanConfig()

    def test_missing_file_returns_default(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.yml"

        with pytest.raises(SystemExit):
            load_config(missing)


class TestConfigValidation:
    """Tests for config validation."""

    def test_unknown_config_key_warns(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text(
            "min_severity: HIGH\n"
            "unknown_option: true\n"
            "another_bad_key: 42\n"
        )

        cfg = load_config(cfg_file)
        captured = capsys.readouterr()

        assert cfg.min_severity == "HIGH"
        assert "unknown config key 'another_bad_key'" in captured.err
        assert "unknown config key 'unknown_option'" in captured.err

    def test_invalid_min_severity_raises(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text("min_severity: SUPER_HIGH\n")

        with pytest.raises(SystemExit, match="invalid min_severity 'SUPER_HIGH'"):
            load_config(cfg_file)

    def test_valid_severities_accepted(self, tmp_path: Path) -> None:
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cfg_file = tmp_path / ".llm-seclint.yml"
            cfg_file.write_text(f"min_severity: {severity}\n")
            cfg = load_config(cfg_file)
            assert cfg.min_severity == severity

    def test_invalid_rule_id_warns(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text(
            "ignore_rules:\n"
            "  - LS001\n"
            "  - SEC002\n"
            "  - bad\n"
        )

        cfg = load_config(cfg_file)
        captured = capsys.readouterr()

        assert "LS001" in cfg.ignore_rules
        assert "invalid rule ID 'SEC002'" in captured.err
        assert "invalid rule ID 'bad'" in captured.err

    def test_directory_traversal_limit(self, tmp_path: Path) -> None:
        """Config search stops after max 5 levels up (or git root)."""
        # Create a deeply nested directory (more than 5 levels)
        deep_dir = tmp_path
        for i in range(8):
            deep_dir = deep_dir / f"level{i}"
        deep_dir.mkdir(parents=True)

        # Place config at the top (8 levels up from deep_dir)
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text("min_severity: LOW\n")

        # Mock cwd to deep_dir and no git root
        with (
            patch("llm_seclint.config.Path.cwd", return_value=deep_dir),
            patch("llm_seclint.config._get_git_root", return_value=None),
        ):
            cfg = load_config()

        # Should NOT find the config because it's more than 5 levels up
        assert cfg.min_severity == "HIGH"  # default, not LOW

    def test_directory_traversal_stops_at_git_root(self, tmp_path: Path) -> None:
        """Config search stops at git root."""
        git_root = tmp_path / "repo"
        sub_dir = git_root / "a" / "b"
        sub_dir.mkdir(parents=True)

        # Place config above git root -- should NOT be found
        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text("min_severity: LOW\n")

        with (
            patch("llm_seclint.config.Path.cwd", return_value=sub_dir),
            patch("llm_seclint.config._get_git_root", return_value=git_root),
        ):
            cfg = load_config()

        assert cfg.min_severity == "HIGH"  # default

    def test_directory_traversal_finds_config_within_limit(self, tmp_path: Path) -> None:
        """Config within 5 levels is found."""
        deep_dir = tmp_path
        for i in range(3):
            deep_dir = deep_dir / f"level{i}"
        deep_dir.mkdir(parents=True)

        cfg_file = tmp_path / ".llm-seclint.yml"
        cfg_file.write_text("min_severity: LOW\n")

        with (
            patch("llm_seclint.config.Path.cwd", return_value=deep_dir),
            patch("llm_seclint.config._get_git_root", return_value=None),
        ):
            cfg = load_config()

        assert cfg.min_severity == "LOW"
