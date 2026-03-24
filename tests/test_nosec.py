"""Tests for # nosec inline suppression."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
from llm_seclint.rules.python.hardcoded_keys import HardcodedApiKeyRule


def _analyze(code: str) -> list:
    analyzer = PythonAnalyzer(rules=[HardcodedApiKeyRule()])
    findings, _error = analyzer.analyze(code, Path("test.py"))
    return findings


class TestNosec:
    def test_nosec_suppresses_all(self) -> None:
        code = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # nosec'
        findings = _analyze(code)
        assert len(findings) == 0

    def test_nosec_specific_rule_suppresses_matching(self) -> None:
        code = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # nosec LS001'
        findings = _analyze(code)
        assert len(findings) == 0

    def test_nosec_specific_rule_does_not_suppress_other(self) -> None:
        code = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # nosec LS002'
        findings = _analyze(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "LS001"

    def test_nosec_multiple_rules(self) -> None:
        code = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # nosec LS001,LS002'
        findings = _analyze(code)
        assert len(findings) == 0

    def test_no_nosec_still_triggers(self) -> None:
        code = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = _analyze(code)
        assert len(findings) >= 1

    def test_nosec_on_different_line_no_effect(self) -> None:
        code = (
            'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n'
            'x = 1  # nosec\n'
        )
        findings = _analyze(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "LS001"

    def test_noqa_nosec_combo(self) -> None:
        code = 'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # noqa nosec'
        findings = _analyze(code)
        assert len(findings) == 0
