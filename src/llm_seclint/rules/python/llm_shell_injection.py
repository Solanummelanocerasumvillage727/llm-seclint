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


# File path patterns indicating CLI/build/dev tooling (not production LLM code)
_CLI_BUILD_DIRS = ("/cli/", "/tools/", "/scripts/")
_CLI_BUILD_FILENAMES = ("setup.py", "setup.cfg", "conftest.py", "manage.py")


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

    @staticmethod
    def _is_cli_or_build_file(file_path: Path) -> bool:
        """Return True if the file is in a CLI/build/scripts directory or is a build file."""
        path_str = str(file_path)
        # Normalise to forward slashes for cross-platform matching
        path_posix = path_str.replace("\\", "/")
        if any(d in path_posix for d in _CLI_BUILD_DIRS):
            return True
        if file_path.name in _CLI_BUILD_FILENAMES:
            return True
        return False

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str]
    ) -> list[Finding]:
        # Skip CLI/build/dev tooling files entirely
        if self._is_cli_or_build_file(file_path):
            return []

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

                if node.args:
                    cmd_arg = node.args[0]
                    is_list_literal = isinstance(cmd_arg, ast.List)
                    is_dynamic = self._is_dynamic(cmd_arg)

                    # Safe pattern: list literal of constants without shell=True
                    # e.g. subprocess.run(["ls", "-la"]) or
                    #      subprocess.run(["ls", "-la"], shell=False)
                    # This is the officially recommended Python pattern.
                    if is_list_literal and not has_shell_true and not is_dynamic:
                        continue

                    # shell=True with a list literal is suspicious misuse
                    # (Python joins list elements into a string for the shell)
                    should_flag = is_dynamic or (has_shell_true and is_list_literal)

                    if should_flag:
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
