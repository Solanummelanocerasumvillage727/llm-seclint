"""Shared test fixtures for llm-seclint tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from llm_seclint.core.finding import Finding
from llm_seclint.rules.base import Rule


@pytest.fixture
def tmp_py_file(tmp_path: Path) -> Path:
    """Return a temporary Python file path."""
    return tmp_path / "test_input.py"


def run_rule_on_code(
    rule: Rule, code: str, file_path: Path | None = None
) -> list[Finding]:
    """Helper to run a rule against a code string and return findings."""
    tree = ast.parse(code)
    source_lines = code.splitlines()
    if file_path is None:
        file_path = Path("test.py")
    return rule.check(tree, file_path, source_lines)
