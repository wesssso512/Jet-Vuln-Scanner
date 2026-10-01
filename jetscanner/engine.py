"""Headless scan orchestration — the one entry point external code calls.

The GUI, the CLI and (later) the queue worker all go through
:func:`run_scan`, so module selection, ordering and per-module error
isolation live here instead of being re-implemented by every front end.
Nothing in this module touches a UI.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from .models import ModuleResult, ScanReport
from .port_scanner import PortScanner
from .validators import normalize_target
from .web_scanner import WebScanner

# (net, web, host, url) -> result. Network modules use ``host``, web modules ``url``.
Runner = Callable[[PortScanner, WebScanner, str, str], ModuleResult]


@dataclass(frozen=True)
class ModuleSpec:
    """A scan module the engine knows how to run.

    ``key`` is the stable public name (used by the CLI ``--modules`` flag and
    the API); ``label`` is the human-readable name.
    """

    key: str
    label: str
    run: Runner


# Registry order is run order, regardless of the order the caller asks in.
MODULES: Dict[str, ModuleSpec] = {
    spec.key: spec
    for spec in (
        ModuleSpec("socket", "Socket Scan",
                   lambda net, web, host, url: net.scan_socket(host)),
        ModuleSpec("nmap", "Nmap Scan",
                   lambda net, web, host, url: net.scan_nmap(host)),
        ModuleSpec("tech", "Tech Fingerprint",
                   lambda net, web, host, url: web.fingerprint(url)),
        ModuleSpec("sqli", "SQL Injection",
                   lambda net, web, host, url: web.check_sqli(url)),
        ModuleSpec("xss", "XSS",
                   lambda net, web, host, url: web.check_xss(url)),
        ModuleSpec("dir", "Directory Busting",
                   lambda net, web, host, url: web.scan_directories(url)),
    )
}


def _select(keys: Iterable[str]) -> List[ModuleSpec]:
    wanted = set(keys)
    if not wanted:
        raise ValueError("Select at least one module.")
    unknown = wanted - MODULES.keys()
    if unknown:
        raise ValueError(
            f"Unknown module(s): {', '.join(sorted(unknown))}. "
            f"Valid modules: {', '.join(MODULES)}."
        )
    return [spec for key, spec in MODULES.items() if key in wanted]


def run_scan(
    target: str,
    modules: Iterable[str],
    on_module_start: Optional[Callable[[ModuleSpec], None]] = None,
    on_result: Optional[Callable[[ModuleResult], None]] = None,
) -> ScanReport:
    """Validate ``target``, run the selected ``modules`` and return the report.

    Raises :class:`~jetscanner.validators.InvalidTarget` for a bad target and
    ``ValueError`` for an empty or unknown module selection — both before any
    traffic is sent. A module that crashes does not abort the scan: its error
    is recorded on its ``ModuleResult`` and the next module runs.

    The optional callbacks fire on the calling thread, once per module, so a
    front end can show progress.
    """
    host, url = normalize_target(target)
    specs = _select(modules)

    report = ScanReport(
        host=host,
        url=url,
        started_at=datetime.datetime.now(datetime.timezone.utc),
    )
    net = PortScanner()
    web = WebScanner()

    for spec in specs:
        if on_module_start:
            on_module_start(spec)
        try:
            result = spec.run(net, web, host, url)
        except Exception as exc:  # defensive: one module never kills the scan
            result = ModuleResult(module=spec.label, error=str(exc))
            result.log(f"[!] Error: {exc}")
        report.results.append(result)
        if on_result:
            on_result(result)

    report.finished_at = datetime.datetime.now(datetime.timezone.utc)
    return report
