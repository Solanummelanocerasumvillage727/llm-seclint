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

    def test_safe_attribute_env_var(self) -> None:
        """Case 3: attribute assignment with os.environ should not trigger."""
        code = 'self.api_key = "os.environ[OPENAI_API_KEY]"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_attribute_shell_var(self) -> None:
        """Case 3: attribute assignment with $ prefix should not trigger."""
        code = 'config.secret_key = "$SECRET_KEY_VALUE"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_attribute_template_var(self) -> None:
        """Case 3: attribute assignment with { prefix should not trigger."""
        code = 'config.api_key = "{API_KEY_PLACEHOLDER}"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_groq_key(self) -> None:
        code = 'GROQ_API_KEY = "gsk_abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS001"

    def test_fireworks_key(self) -> None:
        code = 'FIREWORKS_API_KEY = "fw_abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS001"

    def test_cohere_key(self) -> None:
        code = 'COHERE_API_KEY = "co_abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS001"

    def test_mistral_key(self) -> None:
        code = 'MISTRAL_API_KEY = "mistral-abcdefghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS001"

    def test_groq_key_kwarg(self) -> None:
        code = 'client = Groq(api_key="gsk_abcdefghijklmnopqrstuvwxyz1234567890")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_fireworks_key_kwarg(self) -> None:
        code = 'client = Fireworks(api_key="fw_abcdefghijklmnopqrstuvwxyz1234567890")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    def test_together_key_variable(self) -> None:
        """Together AI has no distinct prefix but variable name triggers detection."""
        code = 'together_key = "abc123defghijklmnopqrstuvwxyz1234567890"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1

    # --- False positive regression tests ---

    def test_safe_cookie_name_constant(self) -> None:
        """Constant names describing token cookie names should NOT trigger."""
        code = 'COOKIE_NAME_ACCESS_TOKEN = "access_token_cookie"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_redis_key_constant(self) -> None:
        """Constant names describing Redis key patterns should NOT trigger."""
        code = 'OAUTH_ACCESS_TOKEN_REDIS_KEY = "oauth:access_token"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_api_key_header_name(self) -> None:
        """Variable holding a header name should NOT trigger."""
        code = 'api_key_header = "X-API-Key"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_url_value(self) -> None:
        """URL values should NOT trigger even if variable name matches API key pattern."""
        code = 'GITHUB_API_KEY_URL = "https://api.github.com/user/keys"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_url_value_http(self) -> None:
        """HTTP URL values should NOT trigger."""
        code = 'API_KEY_ENDPOINT = "http://localhost:8080/api/keys"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_url_kwarg(self) -> None:
        """URL passed as keyword argument should NOT trigger."""
        code = 'client = Client(api_key="https://vault.example.com/v1/secret/key")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_attribute_real_key_still_triggers(self) -> None:
        """Attribute assignment with a real key pattern should STILL trigger."""
        code = 'config.api_key = "sk-proj-abc123def456ghi789jkl012mno345pqr"'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) >= 1
