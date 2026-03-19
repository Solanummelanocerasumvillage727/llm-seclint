"""Severity levels for security findings."""

from enum import Enum


class Severity(str, Enum):
    """Severity level of a security finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __str__(self) -> str:
        return self.value
