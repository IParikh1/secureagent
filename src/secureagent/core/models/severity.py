"""Severity levels for security findings."""

from enum import Enum
from typing import Tuple


class Severity(str, Enum):
    """Severity levels aligned with industry standards (CVSS, SARIF)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sarif_level(self) -> str:
        """Map severity to SARIF level for CI/CD integration."""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        return mapping[self.value]

    @property
    def cvss_range(self) -> Tuple[float, float]:
        """Get CVSS score range for this severity level."""
        ranges = {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0),
        }
        return ranges[self.value]

    @property
    def emoji(self) -> str:
        """Get emoji representation for console output."""
        emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        return emojis[self.value]

    @property
    def color(self) -> str:
        """Get Rich color for console output."""
        colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        return colors[self.value]

    @property
    def priority(self) -> int:
        """Get numeric priority for sorting (lower = more severe)."""
        priorities = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5,
        }
        return priorities[self.value]

    def __lt__(self, other: "Severity") -> bool:
        """Compare severities by priority."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.priority < other.priority

    def __le__(self, other: "Severity") -> bool:
        """Compare severities by priority."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.priority <= other.priority

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Create severity from CVSS score."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        else:
            return cls.INFO
