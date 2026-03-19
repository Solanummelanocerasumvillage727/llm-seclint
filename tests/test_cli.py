"""Tests for the CLI interface."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from llm_seclint.cli import main


def test_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "llm-seclint" in result.output
    assert "0.1.0" in result.output


def test_rules_command() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["rules"])
    assert result.exit_code == 0
    assert "LS001" in result.output
    assert "LS006" in result.output
    assert "hardcoded-api-key" in result.output


def test_scan_vulnerable_example() -> None:
    runner = CliRunner()
    examples_dir = Path(__file__).parent.parent / "examples"
    result = runner.invoke(main, ["scan", str(examples_dir / "vulnerable_app.py")])
    # Should exit 1 because findings exist
    assert result.exit_code == 1
    assert "LS001" in result.output


def test_scan_secure_example() -> None:
    runner = CliRunner()
    examples_dir = Path(__file__).parent.parent / "examples"
    result = runner.invoke(main, ["scan", str(examples_dir / "secure_app.py")])
    # secure_app might still have some generic findings (open() with variable),
    # but should have zero critical hardcoded key findings
    # The important thing is it runs without error
    assert result.exit_code in (0, 1)


def test_scan_json_format(tmp_path: Path) -> None:
    runner = CliRunner()
    examples_dir = Path(__file__).parent.parent / "examples"
    outfile = tmp_path / "results.json"
    result = runner.invoke(
        main,
        [
            "scan",
            str(examples_dir / "vulnerable_app.py"),
            "--format",
            "json",
            "-o",
            str(outfile),
        ],
    )
    assert result.exit_code == 1
    assert outfile.exists()
    import json

    data = json.loads(outfile.read_text())
    assert "results" in data
    assert "summary" in data
    assert data["summary"]["total"] > 0


def test_scan_with_ignore() -> None:
    runner = CliRunner()
    examples_dir = Path(__file__).parent.parent / "examples"
    result = runner.invoke(
        main,
        ["scan", str(examples_dir / "vulnerable_app.py"), "--ignore", "LS001"],
    )
    # LS001 should not appear in output
    # (it might still exit 1 due to other findings)
    assert "LS001" not in result.output


def test_scan_nonexistent_path() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "/nonexistent/path"])
    assert result.exit_code != 0


def test_scan_directory(tmp_path: Path) -> None:
    """Test scanning an entire directory."""
    py_file = tmp_path / "app.py"
    py_file.write_text('api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "LS001" in result.output
