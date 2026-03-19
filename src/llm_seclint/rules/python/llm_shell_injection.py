"""LS004: Detect LLM output passed to shell execution functions."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Functions that execute shell commands
_DANGEROUS_CALLS: dict[str, set[str]] = {
    # module -> function names
    "subprocess": {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"},
    "os": {"system", "popen", "popen2", "popen3", "popen4"},
}

# Standalone dangerous function names (when imported directly)
_DANGEROUS_STANDALONE = {"system", "popen"}


class LlmShellInjectionRule(Rule):
    """Detect LLM output passed to shell execution functions."""

    rule_id = "LS004"
    rule_name = "llm-to-shell-injection"
    severity = Severity.CRITICAL
    description = (
        "LLM output is passed to a shell execution function. "
        "This allows arbitrary command execution if the LLM is compromised."
    )
    cwe_id = "CWE-78"
    owasp_llm = "LLM02: Insecure Output Handling"

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_info = self._classify_call(node)
            if call_info is None:
                continue

            func_display, is_subprocess = call_info

            # For subprocess functions, also check for shell=True
            if is_subprocess:
                has_shell_true = any(
                    isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    and kw.arg == "shell"
                    for kw in node.keywords
                )

                # Check if the command argument contains dynamic content
                if node.args:
                    cmd_arg = node.args[0]
                    if self._is_dynamic(cmd_arg):
                        msg = f"Dynamic output passed to {func_display}"
                        if has_shell_true:
                            msg += " with shell=True"
                        findings.append(
                            self._make_finding(
                                file_path,
                                node.lineno,
                                msg,
                                source_lines,
                                col=node.col_offset,
                                fix_suggestion=(
                                    "Never pass LLM output directly to shell commands. "
                                    "Use an allowlist of permitted commands and validate input."
                                ),
                            )
                        )
            else:
                # os.system, os.popen - always dangerous with dynamic input
                if node.args:
                    cmd_arg = node.args[0]
                    if self._is_dynamic(cmd_arg):
                        findings.append(
                            self._make_finding(
                                file_path,
                                node.lineno,
                                f"Dynamic output passed to {func_display}",
                                source_lines,
                                col=node.col_offset,
                                fix_suggestion=(
                                    "Never pass LLM output to os.system/os.popen. "
                                    "Use subprocess with an argument list and validate input."
                                ),
                            )
                        )

        return findings

    @staticmethod
    def _classify_call(node: ast.Call) -> tuple[str, bool] | None:
        """Classify a call as a dangerous shell function.

        Returns (display_name, is_subprocess) or None.
        """
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                if module in _DANGEROUS_CALLS and attr in _DANGEROUS_CALLS[module]:
                    return f"{module}.{attr}()", module == "subprocess"
        elif isinstance(node.func, ast.Name):
            if node.func.id in _DANGEROUS_STANDALONE:
                return f"{node.func.id}()", False
        return None

    @staticmethod
    def _is_dynamic(node: ast.expr) -> bool:
        """Check if a node represents dynamic (non-constant) content."""
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.List):
            # A list of constants is fine (subprocess argument list)
            return any(not isinstance(el, ast.Constant) for el in node.elts)
        return True
