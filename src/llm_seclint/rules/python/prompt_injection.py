"""LS002: Detect user input concatenated into LLM prompts."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.base import Rule

# Keywords that suggest a string is a prompt
_PROMPT_KEYWORDS = {
    "prompt",
    "system_prompt",
    "user_prompt",
    "system_message",
    "instruction",
    "template",
    "messages",
}

# LLM API call patterns (module.function or just function)
_LLM_CALL_ATTRS = {
    "create",
    "complete",
    "completions",
    "chat",
    "generate",
    "invoke",
}


class PromptConcatInjectionRule(Rule):
    """Detect user input concatenated into prompt strings."""

    rule_id = "LS002"
    rule_name = "prompt-concat-injection"
    severity = Severity.HIGH
    description = (
        "User-controlled input is concatenated directly into an LLM prompt. "
        "This may allow prompt injection attacks."
    )
    cwe_id = "CWE-77"
    owasp_llm = "LLM01: Prompt Injection"

    def check(
        self, tree: ast.Module, file_path: Path, source_lines: list[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        visitor = _PromptInjectionVisitor(self, file_path, source_lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings


class _PromptInjectionVisitor(ast.NodeVisitor):
    """AST visitor that detects prompt injection patterns."""

    def __init__(
        self, rule: PromptConcatInjectionRule, file_path: Path, source_lines: list[str]
    ) -> None:
        self.rule = rule
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: list[Finding] = []
        # Track variable names assigned from prompt-looking strings
        self._prompt_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments to prompt-like variables."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_lower = target.id.lower()
                if any(kw in name_lower for kw in _PROMPT_KEYWORDS):
                    self._prompt_vars.add(target.id)
                    self._check_value(node.value, node.lineno, target.id)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Check f-strings for prompt injection patterns.

        An f-string is suspicious if it contains both static text with
        prompt-like keywords AND dynamic (variable) values.
        """
        has_static_prompt_keyword = False
        has_dynamic_value = False

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text_lower = value.value.lower()
                if any(
                    kw in text_lower
                    for kw in (
                        "you are",
                        "system",
                        "user says",
                        "user input",
                        "answer",
                        "assistant",
                        "respond",
                        "instruction",
                        "query",
                        "question",
                    )
                ):
                    has_static_prompt_keyword = True
            elif isinstance(value, ast.FormattedValue):
                has_dynamic_value = True

        if has_static_prompt_keyword and has_dynamic_value:
            self.findings.append(
                self.rule._make_finding(
                    self.file_path,
                    node.lineno,
                    "User input interpolated into prompt via f-string",
                    self.source_lines,
                    col=node.col_offset,
                    fix_suggestion=(
                        "Separate system prompts from user input. "
                        "Pass user input as a distinct message role."
                    ),
                )
            )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Check string concatenation with + operator."""
        if isinstance(node.op, ast.Add):
            # Check if left side is a prompt-like string
            if self._is_prompt_string(node.left) and self._is_variable(node.right):
                self.findings.append(
                    self.rule._make_finding(
                        self.file_path,
                        node.lineno,
                        "User input concatenated into prompt via + operator",
                        self.source_lines,
                        col=node.col_offset,
                        fix_suggestion="Use separate message roles instead of string concatenation.",
                    )
                )
            elif self._is_variable(node.left) and self._is_prompt_string(node.right):
                self.findings.append(
                    self.rule._make_finding(
                        self.file_path,
                        node.lineno,
                        "User input concatenated into prompt via + operator",
                        self.source_lines,
                        col=node.col_offset,
                        fix_suggestion="Use separate message roles instead of string concatenation.",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check .format() calls on prompt strings."""
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and self._is_prompt_string(node.func.value)
        ):
            self.findings.append(
                self.rule._make_finding(
                    self.file_path,
                    node.lineno,
                    "User input injected into prompt via .format()",
                    self.source_lines,
                    col=node.col_offset,
                    fix_suggestion="Use separate message roles instead of string formatting.",
                )
            )
        self.generic_visit(node)

    def _check_value(self, value: ast.expr, lineno: int, var_name: str) -> None:
        """Check if an assigned value is a concatenated prompt."""
        # Already handled by visit_JoinedStr, visit_BinOp, visit_Call
        pass

    @staticmethod
    def _is_prompt_string(node: ast.expr) -> bool:
        """Check if a node is a string constant with prompt-like content."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text_lower = node.value.lower()
            return any(
                kw in text_lower
                for kw in (
                    "you are",
                    "system",
                    "user says",
                    "user input",
                    "answer the",
                    "assistant",
                    "respond",
                    "instruction",
                    "prompt",
                )
            )
        if isinstance(node, ast.Name):
            name_lower = node.id.lower()
            return any(kw in name_lower for kw in _PROMPT_KEYWORDS)
        return False

    @staticmethod
    def _is_variable(node: ast.expr) -> bool:
        """Check if a node is a variable reference (not a constant)."""
        return isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))
