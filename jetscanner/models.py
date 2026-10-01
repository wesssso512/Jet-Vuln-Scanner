"""Plain data structures shared across the scanner.

The central design decision in V2: scanners return *structured* data
(``Finding`` objects) instead of pre-formatted strings. The UI formats them
for display, the advisor maps them to remediation advice, and the report uses
the same data. Nothing has to scrape a text box to recover what was found.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    """Ordered severity levels. ``rank`` lets us sort findings worst-first."""

    INFO = ("info", 0)
    LOW = ("low", 1)
    MEDIUM = ("medium", 2)
    HIGH = ("high", 3)
    CRITICAL = ("critical", 4)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank


@dataclass
class Finding:
    """A single structured result.

    ``key`` is a stable identifier (e.g. ``"xss"``, ``"port_80"``) used to look
    up advice in the knowledge base. Keep keys in sync with ``advisor.py``.
    """

    key: str
    title: str
    severity: Severity = Severity.INFO
    detail: str = ""


@dataclass
class ModuleResult:
    """Output of one scan module: human-readable log lines + structured findings."""

    module: str
    lines: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def log(self, message: str) -> None:
        self.lines.append(message)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@dataclass
class ScanReport:
    """A complete scan: the normalized target plus each module's result, in
    run order. Timestamps are timezone-aware UTC."""

    host: str
    url: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    results: List[ModuleResult] = field(default_factory=list)

    @property
    def findings(self) -> List[Finding]:
        """Every finding across all modules, worst first.

        The sort is stable, so findings of equal severity keep module order.
        """
        found = [f for r in self.results for f in r.findings]
        return sorted(found, key=lambda f: f.severity.rank, reverse=True)
