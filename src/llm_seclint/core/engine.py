"""Scan engine that orchestrates file discovery, analysis, and reporting."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.analyzers.python_analyzer import PythonAnalyzer
from llm_seclint.config import ScanConfig
from llm_seclint.core.file_discovery import discover_files
from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.rules.registry import RuleRegistry


class ScanEngine:
    """Main scan engine that coordinates the analysis pipeline."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.registry = RuleRegistry()
        self.registry.load_default_rules()
        self._apply_config()

    def _apply_config(self) -> None:
        """Apply configuration to filter rules."""
        if self.config.ignore_rules:
            for rule_id in self.config.ignore_rules:
                self.registry.disable_rule(rule_id)

        if self.config.min_severity:
            severity_order = list(Severity)
            try:
                min_idx = severity_order.index(Severity(self.config.min_severity))
            except ValueError:
                return
            allowed = set(severity_order[: min_idx + 1])
            for rule in list(self.registry.get_enabled_rules()):
                if rule.severity not in allowed:
                    self.registry.disable_rule(rule.rule_id)

    def scan(self, paths: list[Path]) -> list[Finding]:
        """Scan the given paths and return all findings.

        Args:
            paths: Files or directories to scan.

        Returns:
            List of security findings, sorted by file and line.
        """
        files = discover_files(
            paths,
            include_patterns=self.config.include_patterns or None,
            exclude_patterns=self.config.exclude_patterns or None,
        )

        enabled_rules = self.registry.get_enabled_rules()
        if not enabled_rules:
            return []

        analyzer = PythonAnalyzer(rules=enabled_rules)
        findings: list[Finding] = []

        for file_path in files:
            try:
                source = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            file_findings = analyzer.analyze(source, file_path)
            findings.extend(file_findings)

        findings.sort(key=lambda f: (str(f.file_path), f.line))
        return findings

    def get_rules_info(self) -> list[dict[str, str]]:
        """Return information about all registered rules."""
        return [
            {
                "id": rule.rule_id,
                "name": rule.rule_name,
                "severity": str(rule.severity),
                "description": rule.description,
                "enabled": str(rule.rule_id not in self.registry.disabled_rules),
            }
            for rule in self.registry.get_all_rules()
        ]
