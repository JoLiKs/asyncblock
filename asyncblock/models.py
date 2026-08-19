"""Data models for AsyncBlock findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal, Protocol

Severity = Literal["warning", "error"]

_SEVERITY_RANK: dict[Severity, int] = {"warning": 0, "error": 1}


class Serializable(Protocol):
    """Object that can be exported as a plain dictionary."""

    def to_dict(self) -> dict[str, object]: ...


def meets_min_severity(severity: Severity, min_severity: Severity) -> bool:
    """Return whether *severity* meets or exceeds *min_severity*."""
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[min_severity]


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """Summary of a built-in detection rule for documentation and CLI listing."""

    rule_id: str
    patterns: tuple[str, ...]
    suggestion: str
    severity: Severity = "error"

    def to_dict(self) -> dict[str, str | list[str]]:
        """Serialize the rule summary to a plain dictionary."""
        return {
            "rule_id": self.rule_id,
            "patterns": list(self.patterns),
            "suggestion": self.suggestion,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """Aggregated statistics for a set of findings."""

    total: int
    files: int
    errors: int
    warnings: int
    by_rule: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the summary to a plain dictionary."""
        return {
            "total": self.total,
            "files": self.files,
            "errors": self.errors,
            "warnings": self.warnings,
            "by_rule": {rule_id: count for rule_id, count in self.by_rule},
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A single blocking-call detection inside an async context."""

    file: str
    line: int
    col: int
    rule_id: str
    message: str
    suggestion: str
    severity: Severity = "error"

    @property
    def location(self) -> str:
        """Human-readable ``file:line`` location."""
        return f"{self.file}:{self.line}"

    def format_unix(self) -> str:
        """Format as ``file:line:col: RULE_ID: message`` for CI and grep."""
        return f"{self.file}:{self.line}:{self.col}: {self.rule_id}: {self.message}"

    def format_github(self) -> str:
        """Format as a GitHub Actions workflow command for CI annotations."""
        level = "error" if self.severity == "error" else "warning"
        message = f"{self.message} — {self.suggestion}"
        message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return (
            f"::{level} file={self.file},line={self.line},col={self.col},"
            f"title={self.rule_id}::{message}"
        )

    def to_dict(self) -> dict[str, str | int]:
        """Serialize the finding to a plain dictionary."""
        return asdict(self)
