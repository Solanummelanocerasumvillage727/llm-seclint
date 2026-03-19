"""Tests for LS002: Prompt concatenation injection detection."""

from __future__ import annotations

from llm_seclint.rules.python.prompt_injection import PromptConcatInjectionRule
from tests.conftest import run_rule_on_code


def _rule() -> PromptConcatInjectionRule:
    return PromptConcatInjectionRule()


class TestPromptConcatInjection:
    def test_fstring_prompt(self) -> None:
        code = 'prompt = f"You are a helpful bot. User says: {user_input}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "LS002"

    def test_concat_prompt(self) -> None:
        code = 'prompt = "You are a helpful assistant. User input: " + user_input'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_format_prompt(self) -> None:
        code = 'prompt = "You are a bot. The user says: {msg}".format(msg=user_input)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_system_fstring(self) -> None:
        code = 'msg = f"System instruction: respond to {query}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_safe_separate_messages(self) -> None:
        code = '''
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": user_input},
]
'''
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_static_string(self) -> None:
        code = 'prompt = "You are a helpful assistant."'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_non_prompt_fstring(self) -> None:
        code = 'msg = f"Hello {name}, welcome!"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0
