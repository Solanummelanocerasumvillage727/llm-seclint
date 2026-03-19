"""CLI interface for llm-seclint."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from llm_seclint import __version__
from llm_seclint.config import ScanConfig, load_config
from llm_seclint.core.engine import ScanEngine
from llm_seclint.formatters.json_fmt import JsonFormatter
from llm_seclint.formatters.text import TextFormatter


@click.group()
@click.version_option(version=__version__, prog_name="llm-seclint")
def main() -> None:
    """llm-seclint: Static security linter for LLM-powered applications."""


@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    type=click.Path(),
    default=None,
    help="Write output to a file.",
)
@click.option(
    "--ignore",
    "ignore_rules",
    default=None,
    help="Comma-separated list of rule IDs to ignore (e.g., LS001,LS002).",
)
@click.option(
    "--include",
    "include_patterns",
    default=None,
    help='Glob pattern for files to include (e.g., "*.py").',
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    default=None,
    help="Minimum severity to report.",
)
def scan(
    paths: tuple[str, ...],
    output_format: str,
    output_file: str | None,
    ignore_rules: str | None,
    include_patterns: str | None,
    config_path: str | None,
    min_severity: str | None,
) -> None:
    """Scan files or directories for LLM security vulnerabilities."""
    # Load config
    config = load_config(Path(config_path) if config_path else None)

    # CLI overrides
    if output_format:
        config.output_format = output_format
    if ignore_rules:
        config.ignore_rules = list(set(config.ignore_rules) | set(ignore_rules.split(",")))
    if include_patterns:
        config.include_patterns = [include_patterns]
    if min_severity:
        config.min_severity = min_severity

    engine = ScanEngine(config)

    start = time.monotonic()
    target_paths = [Path(p) for p in paths]
    findings = engine.scan(target_paths)
    elapsed = time.monotonic() - start

    # Format output
    if config.output_format == "json":
        formatter = JsonFormatter()
    else:
        formatter = TextFormatter()  # type: ignore[assignment]

    result = formatter.format(findings, elapsed)

    if output_file:
        Path(output_file).write_text(result, encoding="utf-8")
        click.echo(f"Results written to {output_file}")
    else:
        click.echo(result, nl=False)

    # Exit with non-zero if findings found
    if findings:
        sys.exit(1)


@main.command()
def rules() -> None:
    """List all available security rules."""
    engine = ScanEngine()
    rules_info = engine.get_rules_info()

    click.echo()
    click.echo(f"{'ID':<8} {'Name':<30} {'Severity':<10} Description")
    click.echo("-" * 90)
    for rule in rules_info:
        click.echo(
            f"{rule['id']:<8} {rule['name']:<30} {rule['severity']:<10} {rule['description']}"
        )
    click.echo()
