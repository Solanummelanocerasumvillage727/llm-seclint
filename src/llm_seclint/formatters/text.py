"""Rich-based colored terminal formatter."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.text import Text

from llm_seclint.core.finding import Finding
from llm_seclint.core.severity import Severity
from llm_seclint.formatters.base import BaseFormatter

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_SYMBOLS: dict[Severity, str] = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "!",
    Severity.MEDIUM: "~",
    Severity.LOW: "-",
    Severity.INFO: ".",
}


class TextFormatter(BaseFormatter):
    """Format findings as colored terminal output using rich."""

    def format(self, findings: list[Finding], elapsed: float) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)

        if not findings:
            console.print("\n[bold green]No security issues found.[/bold green]")
            console.print(f"Scanned in {elapsed:.2f}s\n")
            return buf.getvalue()

        console.print()

        # Group by file
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            key = str(f.file_path)
            by_file.setdefault(key, []).append(f)

        for file_path, file_findings in by_file.items():
            console.print(f"[bold]{file_path}[/bold]")

            for finding in file_findings:
                color = _SEVERITY_COLORS.get(finding.severity, "white")
                symbol = _SEVERITY_SYMBOLS.get(finding.severity, "?")

                header = Text()
                header.append(f"  {symbol} ", style=color)
                header.append(f"L{finding.line} ", style="dim")
                header.append(f"[{finding.rule_id}] ", style="bold")
                header.append(f"{finding.message}", style=color)
                console.print(header)

                if finding.code_snippet:
                    console.print(f"    [dim]{finding.code_snippet.strip()}[/dim]")

                if finding.fix_suggestion:
                    console.print(f"    [green]Fix: {finding.fix_suggestion}[/green]")

            console.print()

        # Summary
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)

        summary_parts: list[str] = []
        if crit:
            summary_parts.append(f"[bold red]{crit} critical[/bold red]")
        if high:
            summary_parts.append(f"[red]{high} high[/red]")
        if med:
            summary_parts.append(f"[yellow]{med} medium[/yellow]")
        if low:
            summary_parts.append(f"[cyan]{low} low[/cyan]")

        total = len(findings)
        console.print(f"[bold]Found {total} issue(s):[/bold] {', '.join(summary_parts)}")
        console.print(f"Scanned in {elapsed:.2f}s\n")

        return buf.getvalue()
