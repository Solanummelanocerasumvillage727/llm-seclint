"""Tests for LS004: LLM output to shell injection detection."""

from __future__ import annotations

from llm_seclint.rules.python.llm_shell_injection import LlmShellInjectionRule
from tests.conftest import run_rule_on_code


def _rule() -> LlmShellInjectionRule:
    return LlmShellInjectionRule()


class TestLlmShellInjection:
    def test_subprocess_run_shell_true(self) -> None:
        code = 'subprocess.run(llm_output, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS004"
        assert "shell=True" in findings[0].message

    def test_subprocess_call(self) -> None:
        code = 'subprocess.call(command_from_llm, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_os_system(self) -> None:
        code = 'os.system(llm_response)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_os_popen(self) -> None:
        code = 'os.popen(response.content)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_subprocess_popen(self) -> None:
        code = 'subprocess.Popen(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_safe_static_command(self) -> None:
        code = 'subprocess.run("ls -la", shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_argument_list(self) -> None:
        code = 'subprocess.run(["ls", "-la"])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_os_system_static(self) -> None:
        code = 'os.system("echo hello")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_non_shell_function(self) -> None:
        code = 'mylib.run(some_variable)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0
