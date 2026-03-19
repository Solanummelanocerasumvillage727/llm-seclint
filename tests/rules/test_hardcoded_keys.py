"""Tests for LS001: Hardcoded API key detection."""

from __future__ import annotations

from llm_seclint.rules.python.hardcoded_keys import HardcodedApiKeyRule
from tests.conftest import run_rule_on_code


def _rule() -> HardcodedApiKeyRule:
    return HardcodedApiKeyRule()


class TestHardcodedApiKey:
    def test_openai_key_assignment(self) -> None:
        code = 'OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS001"

    def test_openai_attribute_assignment(self) -> None:
        code = 'openai.api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_anthropic_key(self) -> None:
        code = 'ANTHROPIC_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_keyword_arg(self) -> None:
        code = 'client = Anthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_xai_key(self) -> None:
        code = 'XAI_API_KEY = "xai-abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_huggingface_key(self) -> None:
        code = 'HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_safe_env_var(self) -> None:
        code = 'OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_short_string(self) -> None:
        code = 'api_key = "test"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_non_key_variable(self) -> None:
        code = 'username = "some_long_username_that_is_not_a_key_really"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_placeholder(self) -> None:
        code = 'api_key = "${OPENAI_API_KEY}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0
