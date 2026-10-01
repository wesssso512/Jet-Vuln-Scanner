"""Command-line interface::

    jet scan <target> --modules tech,dir --format json [--output FILE]
    jet modules

The result goes to stdout (or ``--output``). Progress, the authorization
notice and errors go to stderr, so ``jet scan ... --format json | jq`` always
sees clean JSON.

Exit codes: 0 scan completed, 1 a finding met ``--fail-on``, 2 usage or I/O
error, 130 interrupted.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, advisor, reporting
from .engine import MODULES, ModuleSpec, run_scan
from .export import to_json, to_sarif_json
from .models import ModuleResult, ScanReport, Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130

NOTICE = ("[!] Only scan systems you own or have explicit written "
          "permission to test.")

_SEVERITIES = {s.label: s for s in Severity}


def _parse_modules(value: str) -> List[str]:
    keys = [k.strip() for k in value.split(",") if k.strip()]
    return list(MODULES) if "all" in keys else keys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jet",
        description="Jet Scanner — network & web vulnerability scanner. "
                    "Authorized use only.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a target")
    scan.add_argument("target", help="domain, IP or full URL "
                                     "(e.g. example.com, http://site.com/p?id=1)")
    scan.add_argument("-m", "--modules", required=True, type=_parse_modules,
                      help=f"comma-separated modules, or 'all' "
                           f"({', '.join(MODULES)})")
    scan.add_argument("-f", "--format", choices=("text", "json", "sarif"),
                      default="text", help="output format (default: text)")
    scan.add_argument("-o", "--output", metavar="FILE",
                      help="write the result to FILE instead of stdout")
    scan.add_argument("--fail-on", choices=list(_SEVERITIES), metavar="SEVERITY",
                      help="exit 1 if any finding is at least this severe "
                           f"({', '.join(_SEVERITIES)})")
    scan.add_argument("-q", "--quiet", action="store_true",
                      help="don't print per-module progress")

    sub.add_parser("modules", help="list available scan modules")
    return parser


def _render(report: ScanReport, fmt: str) -> str:
    if fmt == "json":
        return to_json(report)
    if fmt == "sarif":
        return to_sarif_json(report)
    started = report.started_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    return reporting.build_report(report.url, started, report.results,
                                  advisor.advise(report.findings))


def _cmd_modules() -> int:
    for spec in MODULES.values():
        print(f"{spec.key:<8} {spec.label}")
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    def err(message: str) -> None:
        print(message, file=sys.stderr)

    def on_start(spec: ModuleSpec) -> None:
        err(f"[*] {spec.label} ...")

    def on_result(result: ModuleResult) -> None:
        if result.error:
            err(f"    error: {result.error}")
        else:
            err(f"    {len(result.findings)} finding(s)")

    err(NOTICE)
    try:
        report = run_scan(
            args.target,
            args.modules,
            on_module_start=None if args.quiet else on_start,
            on_result=None if args.quiet else on_result,
        )
    except ValueError as exc:  # includes InvalidTarget
        err(f"jet: error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        err("[!] Interrupted.")
        return EXIT_INTERRUPTED

    content = _render(report, args.format)
    if args.output:
        try:
            Path(args.output).write_text(content + "\n", encoding="utf-8")
        except OSError as exc:
            err(f"jet: error: cannot write {args.output}: {exc}")
            return EXIT_ERROR
        if not args.quiet:
            err(f"[+] Written to {args.output}")
    else:
        print(content)

    if args.fail_on:
        threshold = _SEVERITIES[args.fail_on].rank
        if any(f.severity.rank >= threshold for f in report.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Piped output on Windows would otherwise use the ANSI code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    args = _build_parser().parse_args(argv)
    if args.command == "modules":
        return _cmd_modules()
    return _cmd_scan(args)
