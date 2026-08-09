"""Data models for AsyncBlock findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["warning", "error"]


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

    def to_dict(self) -> dict[str, str | int]:
        """Serialize the finding to a plain dictionary."""
        return asdict(self)
