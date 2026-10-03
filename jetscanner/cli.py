"""Command-line interface::

    jet scan <target> --modules tech,dir --format json [--output FILE]
    jet modules
    jet cloud sites
    jet cloud scan <site> [--checks quick|full|tech,dir] [--format sarif]

``jet cloud`` runs the scan on the hosted platform instead (see ``cloud.py``).

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

from . import __version__, advisor, cloud, reporting
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
    _add_output_options(scan)

    sub.add_parser("modules", help="list available scan modules")

    cloud_cmd = sub.add_parser(
        "cloud", help="scan on the hosted platform (needs CAULK_API_KEY, CAULK_API_URL)")
    cloud_sub = cloud_cmd.add_subparsers(dest="cloud_command", required=True)
    cloud_sub.add_parser("sites", help="list the sites on your account")
    cscan = cloud_sub.add_parser("scan", help="scan one of your sites and wait for the results")
    cscan.add_argument("site", help="host name, URL or id of a site on your account")
    cscan.add_argument("-c", "--checks", default="full",
                       help="quick, full (default) or comma-separated module keys")
    _add_output_options(cscan)
    cscan.add_argument("--timeout", type=float, default=30, metavar="MINUTES",
                       help="stop waiting after this long (default: 30); "
                            "the scan keeps running on the platform")
    return parser


def _add_output_options(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument("-f", "--format", choices=("text", "json", "sarif"),
                     default="text", help="output format (default: text)")
    cmd.add_argument("-o", "--output", metavar="FILE",
                     help="write the result to FILE instead of stdout")
    cmd.add_argument("--fail-on", choices=list(_SEVERITIES), metavar="SEVERITY",
                     help="exit 1 if any finding is at least this severe "
                          f"({', '.join(_SEVERITIES)})")
    cmd.add_argument("-q", "--quiet", action="store_true",
                     help="don't print progress")


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


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _emit(report: ScanReport, args: argparse.Namespace) -> int:
    """Write the report as asked and pick the exit code (shared by the local
    and cloud scans, so both behave the same in CI)."""
    content = _render(report, args.format)
    if args.output:
        try:
            Path(args.output).write_text(content + "\n", encoding="utf-8")
        except OSError as exc:
            _err(f"jet: error: cannot write {args.output}: {exc}")
            return EXIT_ERROR
        if not args.quiet:
            _err(f"[+] Written to {args.output}")
    else:
        print(content)

    if args.fail_on:
        threshold = _SEVERITIES[args.fail_on].rank
        if any(f.severity.rank >= threshold for f in report.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    err = _err

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

    return _emit(report, args)


def _cmd_cloud(args: argparse.Namespace) -> int:
    try:
        client = cloud.CloudClient.from_env()
        if args.cloud_command == "sites":
            for site in client.sites():
                status = "verified" if site["verified"] else "not verified"
                print(f"{site['host']:<40} {status:<13} {site['url']}")
            return EXIT_OK

        log = (lambda message: None) if args.quiet else _err
        site = cloud.find_site(client.sites(), args.site)
        modules = client.modules()
        checks = cloud.resolve_checks(args.checks, site, modules)
        scan = client.start_scan(site["id"], checks)
        log(f"[*] Scan {scan['id']} started on {site['host']} ({', '.join(checks)})")
        scan = client.wait(scan["id"], args.timeout * 60,
                           on_status=lambda status: log(f"[*] {status}"))
        if scan["status"] == "failed":
            raise cloud.CloudError(cloud.failure_message(scan))
        report = cloud.to_report(site, scan, client.findings(scan["id"]), modules)
        log(f"[+] Done: {len(report.findings)} finding(s)")
    except cloud.CloudError as exc:
        _err(f"jet: error: {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _err("[!] Interrupted. The scan keeps running on the platform.")
        return EXIT_INTERRUPTED
    return _emit(report, args)


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Piped output on Windows would otherwise use the ANSI code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    args = _build_parser().parse_args(argv)
    if args.command == "modules":
        return _cmd_modules()
    if args.command == "cloud":
        return _cmd_cloud(args)
    return _cmd_scan(args)
