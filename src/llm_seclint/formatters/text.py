"""Rich-based colored terminal formatter."""

from __future__ import annotations

from collections import defaultdict
from io import StringIO
from pathlib import PurePosixPath

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

    def __init__(
        self,
        use_color: bool = True,
        quiet: bool = False,
        show_groups: bool = True,
    ) -> None:
        self.use_color = use_color
        self.quiet = quiet
        self.show_groups = show_groups

    def format(
        self,
        findings: list[Finding],
        elapsed: float,
        file_count: int = 0,
    ) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=self.use_color, width=120)

        if not findings:
            if not self.quiet:
                console.print("\n[bold green]No security issues found.[/bold green]")
                console.print(f"Scanned {file_count} file(s) in {elapsed:.2f}s\n")
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

        # Grouped summary: group by (rule_id, parent_directory)
        if self.show_groups and not self.quiet:
            groups = self._build_groups(findings)
            if groups:
                console.print("[bold]Grouped summary:[/bold]")
                for (rule_id, directory, message), count in sorted(
                    groups.items(), key=lambda x: -x[1]
                ):
                    console.print(
                        f"  {rule_id}: {count} similar findings in "
                        f"{directory} ({message})"
                    )
                console.print()

        if not self.quiet:
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
            console.print(
                f"[bold]Found {total} issue(s):[/bold] {', '.join(summary_parts)}"
            )
            console.print(f"Scanned {file_count} file(s) in {elapsed:.2f}s\n")

        return buf.getvalue()

    @staticmethod
    def _build_groups(
        findings: list[Finding],
    ) -> dict[tuple[str, str, str], int]:
        """Build grouped counts for findings sharing the same rule and directory.

        Groups are only included when there are 5 or more findings with the
        same ``(rule_id, parent_directory)`` combination.

        Returns:
            Mapping from ``(rule_id, directory, message)`` to count.
        """
        counter: dict[tuple[str, str, str], int] = defaultdict(int)
        for f in findings:
            parent = str(PurePosixPath(f.file_path).parent)
            # Ensure trailing slash for clarity
            if not parent.endswith("/"):
                parent += "/"
            counter[(f.rule_id, parent, f.message)] += 1

        # Only keep groups with 5+ findings
        return {key: count for key, count in counter.items() if count >= 5}
