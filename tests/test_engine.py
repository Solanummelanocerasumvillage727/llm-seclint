"""Tests for the scan engine."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.config import ScanConfig
from llm_seclint.core.engine import ScanEngine


def test_engine_scans_files(tmp_path: Path) -> None:
    py_file = tmp_path / "test.py"
    py_file.write_text('OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')

    engine = ScanEngine()
    findings = engine.scan([tmp_path])
    assert len(findings) >= 1
    assert findings[0].rule_id == "LS001"


def test_engine_respects_ignore_rules(tmp_path: Path) -> None:
    py_file = tmp_path / "test.py"
    py_file.write_text('OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n')

    config = ScanConfig(ignore_rules=["LS001"])
    engine = ScanEngine(config)
    findings = engine.scan([tmp_path])
    assert all(f.rule_id != "LS001" for f in findings)


def test_engine_no_files(tmp_path: Path) -> None:
    engine = ScanEngine()
    findings = engine.scan([tmp_path])
    assert findings == []


def test_engine_skips_syntax_errors(tmp_path: Path) -> None:
    py_file = tmp_path / "bad.py"
    py_file.write_text("def foo(\n")  # syntax error

    engine = ScanEngine()
    findings = engine.scan([tmp_path])
    assert findings == []


def test_engine_get_rules_info() -> None:
    engine = ScanEngine()
    info = engine.get_rules_info()
    assert len(info) == 6
    ids = {r["id"] for r in info}
    assert ids == {"LS001", "LS002", "LS003", "LS004", "LS005", "LS006"}


def test_engine_scans_single_file(tmp_path: Path) -> None:
    py_file = tmp_path / "app.py"
    py_file.write_text('key = eval(user_input)\n')

    engine = ScanEngine()
    findings = engine.scan([py_file])
    assert len(findings) >= 1
