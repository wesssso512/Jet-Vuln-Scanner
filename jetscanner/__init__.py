"""Jet Vulnerability Scanner — V2.

A multi-module security scanner (network + web) usable as a headless
library. The package is intentionally split by responsibility:

    engine      -> headless orchestration: run_scan() + the module registry
    export      -> machine-readable output (JSON, SARIF 2.1.0)
    models     -> plain data structures (Finding, ModuleResult, ScanReport, Severity)
    validators  -> target parsing / validation / normalization
    port_scanner-> network layer (socket + optional nmap)
    web_scanner -> web layer (fingerprint, SQLi, XSS, dir busting)
    advisor     -> rule-based knowledge base (findings -> remediation advice)
    reporting   -> text report building + cross-platform file opening
    ui          -> Tkinter GUI (the only module that touches Tk; never
                   imported by the package itself)

Library usage::

    from jetscanner import run_scan, to_json

    report = run_scan("example.com", ["tech", "dir"])
    for finding in report.findings:  # worst first
        print(finding.severity.label, finding.title)
    print(to_json(report))

Only scan systems you own or have explicit written permission to test.
"""

__version__ = "2.0.0"

from .engine import MODULES, ModuleSpec, run_scan
from .export import to_dict, to_json, to_sarif, to_sarif_json
from .models import Finding, ModuleResult, ScanReport, Severity
from .validators import InvalidTarget

__all__ = [
    "MODULES",
    "Finding",
    "InvalidTarget",
    "ModuleResult",
    "ModuleSpec",
    "ScanReport",
    "Severity",
    "run_scan",
    "to_dict",
    "to_json",
    "to_sarif",
    "to_sarif_json",
]
