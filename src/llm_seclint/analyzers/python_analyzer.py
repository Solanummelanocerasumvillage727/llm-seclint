"""Python AST-based analyzer."""

from __future__ import annotations

import ast
from pathlib import Path

from llm_seclint.analyzers.base import BaseAnalyzer
from llm_seclint.core.finding import Finding
from llm_seclint.rules.base import Rule


class PythonAnalyzer(BaseAnalyzer):
    """Analyzer that parses Python source into an AST and runs rules against it."""

    def __init__(self, rules: list[Rule]) -> None:
        super().__init__(rules)

    def analyze(self, source: str, file_path: Path) -> list[Finding]:
        """Parse Python source and run all rules against the AST.

        Args:
            source: Python source code.
            file_path: Path to the source file.

        Returns:
            List of findings from all rules.
        """
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            return []

        source_lines = source.splitlines()
        findings: list[Finding] = []

        for rule in self.rules:
            rule_findings = rule.check(tree, file_path, source_lines)
            findings.extend(rule_findings)

        return findings
