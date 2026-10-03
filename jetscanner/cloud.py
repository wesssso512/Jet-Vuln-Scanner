"""Run scans on the hosted platform from the command line (``jet cloud``).

The platform does the scanning (and enforces ownership verification); this
module starts a scan, waits for it, and turns the results into a
``ScanReport`` so the existing text / JSON / SARIF output and ``--fail-on``
work exactly as they do for local scans.

Configuration comes from the environment, never from flags, so the key
doesn't end up in shell history or in the process list:

* ``CAULK_API_KEY`` — an API key from the dashboard (``ck_live_…``)
* ``CAULK_API_URL`` — the platform's API address
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests

from .models import Finding, ModuleResult, ScanReport, Severity

API_KEY_ENV = "CAULK_API_KEY"
API_URL_ENV = "CAULK_API_URL"
POLL_SECONDS = 5

_SEVERITIES = {s.label: s for s in Severity}

# Why a platform scan failed (its error_code), in words a CI log reader can act on.
_FAILURE_REASONS = {
    "not_verified": "the site isn't verified anymore. Verify it in the dashboard.",
    "unresolvable": "the site's domain no longer resolves.",
    "private_target": "the site's address now points to a private network.",
    "invalid_target": "the platform couldn't use the site's address.",
    "internal": "something went wrong on the platform. Try again.",
    "queue_unavailable": "the platform couldn't start the scan. Try again shortly.",
}


class CloudError(Exception):
    """Something the user has to fix; the message says what."""


class CloudClient:
    def __init__(self, base_url: str, api_key: str,
                 session: Optional[requests.Session] = None, timeout: float = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = session or requests.Session()
        self.timeout = timeout

    @classmethod
    def from_env(cls, environ: Optional[Dict[str, str]] = None) -> "CloudClient":
        env = os.environ if environ is None else environ
        key = env.get(API_KEY_ENV, "").strip()
        url = env.get(API_URL_ENV, "").strip()
        if not key:
            raise CloudError(f"Set {API_KEY_ENV} to an API key from the dashboard "
                             "(Settings → API keys).")
        if not url:
            raise CloudError(f"Set {API_URL_ENV} to the platform's API address.")
        if urlparse(url).scheme not in ("http", "https"):
            raise CloudError(f"{API_URL_ENV} must start with https:// (or http:// locally).")
        return cls(url, key)

    # -- HTTP ---------------------------------------------------------------
    def _request(self, method: str, path: str, body: Any = None) -> Any:
        try:
            resp = self.session.request(
                method, self.base_url + path, json=body, timeout=self.timeout,
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Accept": "application/json"})
        except requests.RequestException as exc:
            raise CloudError(f"Can't reach {self.base_url}: {exc}") from exc

        try:
            data = resp.json()
        except ValueError:
            data = None
        if resp.status_code < 400:
            return data

        detail = data.get("detail") if isinstance(data, dict) else None
        message = detail.get("message") if isinstance(detail, dict) else detail
        code = detail.get("code") if isinstance(detail, dict) else None
        if resp.status_code == 401:
            raise CloudError(f"The API key was rejected. Check {API_KEY_ENV} "
                             "(it may have been revoked).")
        if code == "scan_in_progress":
            raise CloudError("A scan is already running on this account "
                             f"(scan {detail.get('scan_id')}). Wait for it to finish.")
        raise CloudError(message or f"The platform answered HTTP {resp.status_code}.")

    # -- API ----------------------------------------------------------------
    def sites(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/targets")

    def modules(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/scans/modules")

    def start_scan(self, target_id: str, modules: List[str]) -> Dict[str, Any]:
        return self._request("POST", "/scans", {"target_id": target_id, "modules": modules})

    def scan(self, scan_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}")

    def findings(self, scan_id: str) -> List[Dict[str, Any]]:
        return self._request("GET", f"/scans/{scan_id}/findings")

    def wait(self, scan_id: str, timeout_s: float,
             on_status: Optional[Callable[[str], None]] = None,
             sleep: Optional[Callable[[float], None]] = None,
             clock: Optional[Callable[[], float]] = None) -> Dict[str, Any]:
        """Poll until the scan is done or failed; ``CloudError`` on timeout."""
        sleep = sleep or time.sleep
        clock = clock or time.monotonic
        deadline = clock() + timeout_s
        last = None
        while True:
            scan = self.scan(scan_id)
            if scan["status"] != last:
                last = scan["status"]
                if on_status:
                    on_status(last)
            if scan["status"] in ("done", "failed"):
                return scan
            if clock() >= deadline:
                raise CloudError(f"Gave up waiting after {timeout_s / 60:g} minutes. "
                                 f"The scan ({scan_id}) keeps running on the platform.")
            sleep(POLL_SECONDS)


# -- helpers ------------------------------------------------------------------
def _host(value: str) -> str:
    value = value.strip().lower()
    parsed = urlparse(value if "://" in value else "//" + value)
    return (parsed.hostname or value).rstrip(".")


def find_site(sites: List[Dict[str, Any]], query: str) -> Dict[str, Any]:
    """The site matching an id, a URL or a bare host name."""
    for site in sites:
        if query in (site["id"], site["url"]):
            return site
    matches = [s for s in sites if s["host"] == _host(query)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        urls = ", ".join(s["url"] for s in matches)
        raise CloudError(f"Several sites match {query!r} ({urls}). Pass the full URL.")
    known = ", ".join(sorted(s["host"] for s in sites)) or "none yet"
    raise CloudError(f"No site {query!r} on this account (yours: {known}). "
                     "Add and verify it in the dashboard first.")


def resolve_checks(spec: str, site: Dict[str, Any],
                   modules: List[Dict[str, Any]]) -> List[str]:
    """``quick`` (no verification needed), ``full`` (everything) or a
    comma-separated list of module keys."""
    known = {m["key"]: m for m in modules}
    spec = spec.strip().lower()
    if spec == "quick":
        return [k for k, m in known.items() if not m["needs_verification"]]
    if spec == "full":
        chosen = list(known)
        # nmap covers the socket scan's ports (and adds versions): running
        # both would report the same open port twice.
        if "nmap" in known and "socket" in known:
            chosen.remove("socket")
    else:
        chosen = [k.strip() for k in spec.split(",") if k.strip()]
        unknown = [k for k in chosen if k not in known]
        if unknown or not chosen:
            raise CloudError(f"Unknown check(s): {', '.join(unknown) or spec!r}. "
                             f"Use quick, full or any of: {', '.join(known)}.")
    blocked = [k for k in chosen if known[k]["needs_verification"]]
    if blocked and not site["verified"]:
        raise CloudError(f"{site['host']} isn't verified, so these checks can't run: "
                         f"{', '.join(blocked)}. Verify it in the dashboard, "
                         "or use --checks quick.")
    return chosen


def failure_message(scan: Dict[str, Any]) -> str:
    reason = _FAILURE_REASONS.get(scan.get("error_code") or "",
                                  scan.get("error") or "unknown reason.")
    return f"The scan didn't finish: {reason}"


def _time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def to_report(site: Dict[str, Any], scan: Dict[str, Any], findings: List[Dict[str, Any]],
              modules: List[Dict[str, Any]]) -> ScanReport:
    """A finished platform scan as an engine ``ScanReport``."""
    label_of = {m["key"]: m["label"] for m in modules}
    results: Dict[str, ModuleResult] = {}
    for key in scan["modules"]:
        label = label_of.get(key, key)
        results[label] = ModuleResult(module=label)
    for f in findings:
        result = results.setdefault(f["module"], ModuleResult(module=f["module"]))
        result.add(Finding(f["key"], f["title"],
                           _SEVERITIES.get(f["severity"], Severity.INFO), f.get("detail", "")))
    for err in scan.get("module_errors", []):
        label = label_of.get(err["module"], err["module"])
        results.setdefault(label, ModuleResult(module=label)).error = err["error"]
    # The platform keeps the engine's raw log to itself; give the text report
    # one line per finding instead of "(no output)".
    for result in results.values():
        for f in result.findings:
            result.log(f"[+] {f.title}" + (f" ({f.detail})" if f.detail else ""))
        if not result.findings and not result.error:
            result.log("[-] No findings.")

    started = _time(scan.get("started_at")) or _time(scan["created_at"])
    return ScanReport(host=site["host"], url=site["url"], started_at=started,
                      finished_at=_time(scan.get("finished_at")),
                      results=list(results.values()))
