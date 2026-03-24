"""Tests for LS003: LLM output to SQL injection detection."""

from __future__ import annotations

from llm_seclint.rules.python.llm_sql_injection import LlmSqlInjectionRule
from tests.conftest import run_rule_on_code


def _rule() -> LlmSqlInjectionRule:
    return LlmSqlInjectionRule()


class TestLlmSqlInjection:
    def test_fstring_sql(self) -> None:
        code = 'cursor.execute(f"SELECT * FROM users WHERE name = \'{user_input}\'")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS003"

    def test_concat_sql(self) -> None:
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + llm_response)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_format_sql(self) -> None:
        code = 'db.execute("DELETE FROM logs WHERE id = {}".format(response))'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_percent_format_sql(self) -> None:
        code = 'cursor.execute("UPDATE users SET name = \'%s\'" % llm_output)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_safe_parameterized(self) -> None:
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_static_query(self) -> None:
        code = 'cursor.execute("SELECT COUNT(*) FROM users")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_constant_concat(self) -> None:
        """Pure constant concatenation should not trigger (no dynamic part)."""
        code = 'cursor.execute("SELECT " + "* FROM users")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_non_sql_execute(self) -> None:
        code = 'task.execute(some_variable)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0
