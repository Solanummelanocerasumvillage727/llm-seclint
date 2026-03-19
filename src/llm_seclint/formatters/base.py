"""Abstract base class for output formatters."""

from __future__ import annotations

import abc

from llm_seclint.core.finding import Finding


class BaseFormatter(abc.ABC):
    """Abstract base class for formatting scan results."""

    @abc.abstractmethod
    def format(self, findings: list[Finding], elapsed: float) -> str:
        """Format a list of findings into a string.

        Args:
            findings: List of security findings.
            elapsed: Elapsed scan time in seconds.

        Returns:
            Formatted string output.
        """
        ...
