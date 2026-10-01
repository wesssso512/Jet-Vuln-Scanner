"""Machine-readable output: JSON and SARIF 2.1.0.

Both formats are built from the same ``ScanReport`` the engine returns, and
use the ``Finding`` field names (``key``, ``title``, ``severity``,
``detail``) unchanged, so the vocabulary is identical from the engine to the
API to the database. These functions only build data; writing files is the
caller's job.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .advisor import KNOWLEDGE_BASE
from .models import Finding, ModuleResult, ScanReport, Severity

# Bump when the JSON shape changes in a way consumers must handle.
SCHEMA_VERSION = "1"

_TOOL_NAME = "jetscanner"

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub code scanning buckets: >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium,
# 0.1-3.9 low. Placeholder scores per level until real CVSS lands (Phase 2).
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def _ranked(report: ScanReport) -> List[Tuple[ModuleResult, Finding]]:
    """(module, finding) pairs, worst first; stable within a severity."""
    pairs = [(r, f) for r in report.results for f in r.findings]
    return sorted(pairs, key=lambda p: p[1].severity.rank, reverse=True)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _sarif_time(value: datetime) -> str:
    """SARIF wants UTC with a ``Z`` suffix, e.g. ``2026-10-01T03:41:23.511Z``."""
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


# -- JSON -----------------------------------------------------------------
def to_dict(report: ScanReport) -> Dict[str, Any]:
    """The report as plain JSON-serializable data."""
    ranked = _ranked(report)
    summary: Dict[str, int] = {"total": len(ranked)}
    for severity in sorted(Severity, key=lambda s: s.rank, reverse=True):
        summary[severity.label] = sum(
            1 for _, f in ranked if f.severity is severity)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": _TOOL_NAME, "version": __version__},
        "target": {"host": report.host, "url": report.url},
        "started_at": _iso(report.started_at),
        "finished_at": _iso(report.finished_at),
        "summary": summary,
        "findings": [
            {
                "key": f.key,
                "title": f.title,
                "severity": f.severity.label,
                "detail": f.detail,
                "module": module.module,
            }
            for module, f in ranked
        ],
        "modules": [
            {"module": r.module, "error": r.error, "log": list(r.lines)}
            for r in report.results
        ],
    }


def to_json(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(to_dict(report), indent=indent, ensure_ascii=False)


# -- SARIF ----------------------------------------------------------------
def to_sarif(report: ScanReport) -> Dict[str, Any]:
    """The report as a SARIF 2.1.0 log (one run).

    Each distinct finding ``key`` becomes a rule; its text comes from the
    advisor knowledge base when there is an entry. Findings are located at
    the scanned URL, since they describe a live site rather than a source
    file. Module errors are reported as tool notifications, not results.
    """
    ranked = _ranked(report)

    rules: List[Dict[str, Any]] = []
    rule_index: Dict[str, int] = {}
    for _, f in ranked:
        if f.key in rule_index:
            continue  # first occurrence is the worst, since ``ranked`` is sorted
        rule_index[f.key] = len(rules)
        title, help_text = KNOWLEDGE_BASE.get(f.key, (f.title, f.title))
        rules.append({
            "id": f.key,
            "shortDescription": {"text": title},
            "help": {"text": help_text},
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "tags": ["security"],
            },
        })

    results = []
    for module, f in ranked:
        message = f"{f.title}: {f.detail}" if f.detail else f.title
        results.append({
            "ruleId": f.key,
            "ruleIndex": rule_index[f.key],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": report.url}},
            }],
            "properties": {"severity": f.severity.label, "module": module.module},
        })

    errors = [r for r in report.results if r.error]
    invocation: Dict[str, Any] = {
        "executionSuccessful": not errors,
        "toolExecutionNotifications": [
            {"level": "error", "message": {"text": f"{r.module}: {r.error}"}}
            for r in errors
        ],
    }
    invocation["startTimeUtc"] = _sarif_time(report.started_at)
    if report.finished_at is not None:
        invocation["endTimeUtc"] = _sarif_time(report.finished_at)

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": _TOOL_NAME,
                "version": __version__,
                "rules": rules,
            }},
            "invocations": [invocation],
            "results": results,
        }],
    }


def to_sarif_json(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(to_sarif(report), indent=indent, ensure_ascii=False)
