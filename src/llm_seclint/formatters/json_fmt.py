"""JSON output formatter."""

from __future__ import annotations

import json

from llm_seclint.core.finding import Finding
from llm_seclint.formatters.base import BaseFormatter


class JsonFormatter(BaseFormatter):
    """Format findings as a JSON array."""

    def format(
        self,
        findings: list[Finding],
        elapsed: float,
        file_count: int = 0,
    ) -> str:
        output = {
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity.value == "CRITICAL"),
                "high": sum(1 for f in findings if f.severity.value == "HIGH"),
                "medium": sum(1 for f in findings if f.severity.value == "MEDIUM"),
                "low": sum(1 for f in findings if f.severity.value == "LOW"),
                "info": sum(1 for f in findings if f.severity.value == "INFO"),
            },
            "files_scanned": file_count,
            "elapsed_seconds": round(elapsed, 3),
        }
        return json.dumps(output, indent=2) + "\n"
