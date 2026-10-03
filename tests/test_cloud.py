"""Tests for ``jet cloud``: the platform client, its helpers and the CLI
commands. A fake HTTP session stands in for the platform; no network."""
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import requests

from jetscanner import cli, cloud
from jetscanner.models import Severity

URL = "https://api.example.test"
KEY = "ck_live_testkey"

SITE = {"id": "site-1", "host": "example.com", "url": "https://example.com",
        "verified": True}
UNVERIFIED = dict(SITE, id="site-2", host="other.com", url="https://other.com",
                  verified=False)
MODULES = [
    {"key": "socket", "label": "Socket Scan", "needs_verification": True},
    {"key": "nmap", "label": "Nmap Scan", "needs_verification": True},
    {"key": "tech", "label": "Tech Fingerprint", "needs_verification": False},
    {"key": "xss", "label": "XSS", "needs_verification": True},
]
RUNNING = {"id": "scan-1", "status": "running", "modules": ["tech", "xss"],
           "created_at": "2026-10-03T10:00:00Z", "started_at": "2026-10-03T10:00:01Z",
           "finished_at": None, "error": None, "error_code": None, "module_errors": []}
DONE = dict(RUNNING, status="done", finished_at="2026-10-03T10:02:00Z",
            module_errors=[{"module": "nmap", "error": "Nmap scan timed out."}])
FINDINGS = [
    {"key": "xss", "title": "Reflected XSS", "severity": "high",
     "detail": "action=/search", "module": "XSS"},
    {"key": "nginx", "title": "nginx server detected", "severity": "info",
     "detail": "nginx/1.25", "module": "Tech Fingerprint"},
]


class FakeResponse:
    def __init__(self, status, data):
        self.status_code, self._data = status, data

    def json(self):
        if self._data is None:
            raise ValueError("no body")
        return self._data


class Seq(list):
    """Successive answers for one route; the last one repeats."""


class FakeSession:
    """Answers (method, path) from a table. A plain value is the JSON body
    (status 200), a tuple is (status, body), a Seq answers in turn."""

    def __init__(self, routes):
        self.routes = {k: Seq(v) if isinstance(v, Seq) else v for k, v in routes.items()}
        self.calls = []

    def request(self, method, url, json=None, timeout=None, headers=None):
        path = url[len(URL):]
        self.calls.append((method, path, json, headers))
        answer = self.routes[(method, path)]
        if isinstance(answer, Seq):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if isinstance(answer, Exception):
            raise answer
        status, data = answer if isinstance(answer, tuple) else (200, answer)
        return FakeResponse(status, data)


def client(routes):
    return cloud.CloudClient(URL + "/", KEY, session=FakeSession(routes))


class FromEnvTests(unittest.TestCase):
    def test_needs_a_key(self):
        with self.assertRaisesRegex(cloud.CloudError, "CAULK_API_KEY"):
            cloud.CloudClient.from_env({"CAULK_API_URL": URL})

    def test_needs_an_url_no_default(self):
        # No built-in address until the domain is ours: never send keys to
        # a host we don't control.
        with self.assertRaisesRegex(cloud.CloudError, "CAULK_API_URL"):
            cloud.CloudClient.from_env({"CAULK_API_KEY": KEY})

    def test_url_must_be_http(self):
        with self.assertRaisesRegex(cloud.CloudError, "https://"):
            cloud.CloudClient.from_env({"CAULK_API_KEY": KEY, "CAULK_API_URL": "api.example.test"})

    def test_ok(self):
        c = cloud.CloudClient.from_env({"CAULK_API_KEY": KEY, "CAULK_API_URL": URL + "/"})
        self.assertEqual((c.base_url, c.api_key), (URL, KEY))


class RequestTests(unittest.TestCase):
    def test_sends_the_key_as_bearer(self):
        c = client({("GET", "/targets"): [SITE]})
        self.assertEqual(c.sites(), [SITE])
        _, _, _, headers = c.session.calls[0]
        self.assertEqual(headers["Authorization"], f"Bearer {KEY}")

    def test_rejected_key(self):
        c = client({("GET", "/targets"): (401, {"detail": "Not authenticated."})})
        with self.assertRaisesRegex(cloud.CloudError, "rejected.*revoked"):
            c.sites()

    def test_platform_message_is_passed_on(self):
        c = client({("POST", "/scans"): (403, {"detail": {
            "code": "email_not_verified", "message": "Confirm your email address first."}})})
        with self.assertRaisesRegex(cloud.CloudError, "Confirm your email"):
            c.start_scan("site-1", ["tech"])

    def test_scan_already_running(self):
        c = client({("POST", "/scans"): (429, {"detail": {
            "code": "scan_in_progress", "message": "busy", "scan_id": "scan-9"}})})
        with self.assertRaisesRegex(cloud.CloudError, "already running.*scan-9"):
            c.start_scan("site-1", ["tech"])

    def test_unreachable(self):
        c = client({("GET", "/targets"): requests.ConnectionError("refused")})
        with self.assertRaisesRegex(cloud.CloudError, "Can't reach"):
            c.sites()

    def test_non_json_error(self):
        c = client({("GET", "/targets"): (502, None)})
        with self.assertRaisesRegex(cloud.CloudError, "HTTP 502"):
            c.sites()


class FindSiteTests(unittest.TestCase):
    sites = [SITE, UNVERIFIED]

    def test_by_host_url_or_id(self):
        for query in ["example.com", "https://Example.com/", "EXAMPLE.COM",
                      "https://example.com", "site-1"]:
            self.assertEqual(cloud.find_site(self.sites, query)["id"], "site-1", query)

    def test_unknown_lists_the_known_ones(self):
        with self.assertRaisesRegex(cloud.CloudError, "example.com, other.com.*dashboard"):
            cloud.find_site(self.sites, "nope.com")

    def test_ambiguous_host_asks_for_the_url(self):
        twins = [SITE, dict(SITE, id="site-3", url="https://example.com/shop")]
        with self.assertRaisesRegex(cloud.CloudError, "Several sites"):
            cloud.find_site(twins, "example.com")
        self.assertEqual(cloud.find_site(twins, "https://example.com/shop")["id"], "site-3")


class ResolveChecksTests(unittest.TestCase):
    def test_quick_is_what_needs_no_verification(self):
        self.assertEqual(cloud.resolve_checks("quick", UNVERIFIED, MODULES), ["tech"])

    def test_full_skips_socket_when_nmap_is_there(self):
        self.assertEqual(cloud.resolve_checks("full", SITE, MODULES), ["nmap", "tech", "xss"])

    def test_full_on_an_unverified_site_explains(self):
        with self.assertRaisesRegex(cloud.CloudError, "isn't verified.*--checks quick"):
            cloud.resolve_checks("full", UNVERIFIED, MODULES)

    def test_explicit_list(self):
        self.assertEqual(cloud.resolve_checks("tech, xss", SITE, MODULES), ["tech", "xss"])
        self.assertEqual(cloud.resolve_checks("tech", UNVERIFIED, MODULES), ["tech"])

    def test_unknown_check(self):
        with self.assertRaisesRegex(cloud.CloudError, "Unknown check.*sqlx"):
            cloud.resolve_checks("tech,sqlx", SITE, MODULES)


class WaitTests(unittest.TestCase):
    def test_polls_until_done_and_reports_changes(self):
        c = client({("GET", "/scans/scan-1"): Seq([
            dict(RUNNING, status="pending"), RUNNING, RUNNING, DONE])})
        seen, sleeps = [], []
        scan = c.wait("scan-1", 600, on_status=seen.append, sleep=sleeps.append,
                      clock=lambda: 0)
        self.assertEqual(scan["status"], "done")
        self.assertEqual(seen, ["pending", "running", "done"])
        self.assertEqual(sleeps, [cloud.POLL_SECONDS] * 3)

    def test_gives_up_after_the_timeout(self):
        c = client({("GET", "/scans/scan-1"): RUNNING})
        now = [0.0]

        def sleep(seconds):
            now[0] += seconds

        with self.assertRaisesRegex(cloud.CloudError, "keeps running"):
            c.wait("scan-1", 12, sleep=sleep, clock=lambda: now[0])


class ToReportTests(unittest.TestCase):
    def test_platform_results_become_an_engine_report(self):
        report = cloud.to_report(SITE, DONE, FINDINGS, MODULES)
        self.assertEqual((report.host, report.url), ("example.com", "https://example.com"))
        self.assertEqual(report.started_at.isoformat(), "2026-10-03T10:00:01+00:00")
        by_module = {r.module: r for r in report.results}
        self.assertEqual(by_module["XSS"].findings[0].severity, Severity.HIGH)
        self.assertEqual(by_module["Tech Fingerprint"].findings[0].key, "nginx")
        self.assertEqual(by_module["Nmap Scan"].error, "Nmap scan timed out.")
        self.assertEqual([f.key for f in report.findings], ["xss", "nginx"])  # worst first
        self.assertEqual(by_module["XSS"].lines, ["[+] Reflected XSS (action=/search)"])

    def test_module_without_findings_says_so(self):
        report = cloud.to_report(SITE, dict(DONE, module_errors=[]), [], MODULES)
        self.assertEqual([r.lines for r in report.results], [["[-] No findings."]] * 2)

    def test_failure_message_in_plain_words(self):
        failed = dict(DONE, status="failed", error_code="private_target")
        self.assertIn("private network", cloud.failure_message(failed))
        odd = dict(DONE, status="failed", error_code=None, error="Boom.")
        self.assertIn("Boom.", cloud.failure_message(odd))


class CliTests(unittest.TestCase):
    def run_cli(self, argv, routes):
        c = client(routes)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cloud.CloudClient, "from_env", return_value=c), \
                mock.patch("jetscanner.cloud.time.sleep"), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue(), c.session.calls

    def scan_routes(self, scan_states, findings=FINDINGS):
        return {
            ("GET", "/targets"): [SITE, UNVERIFIED],
            ("GET", "/scans/modules"): MODULES,
            ("POST", "/scans"): (202, dict(RUNNING, status="pending")),
            ("GET", "/scans/scan-1"): Seq(scan_states),
            ("GET", "/scans/scan-1/findings"): findings,
        }

    def test_sites(self):
        code, out, _, _ = self.run_cli(["cloud", "sites"],
                                       {("GET", "/targets"): [SITE, UNVERIFIED]})
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("example.com", out)
        self.assertIn("not verified", out)

    def test_scan_sarif_and_fail_on(self):
        code, out, err, calls = self.run_cli(
            ["cloud", "scan", "example.com", "--format", "sarif", "--fail-on", "high"],
            self.scan_routes([RUNNING, DONE]))
        self.assertEqual(code, cli.EXIT_FINDINGS)
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("xss", rules)
        post = [c for c in calls if c[0] == "POST"][0]
        self.assertEqual(post[2], {"target_id": "site-1", "modules": ["nmap", "tech", "xss"]})
        self.assertIn("Scan scan-1 started on example.com", err)

    def test_scan_below_threshold_passes(self):
        code, out, _, _ = self.run_cli(
            ["cloud", "scan", "example.com", "-f", "json", "--fail-on", "critical", "-q"],
            self.scan_routes([DONE]))
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(json.loads(out)["summary"]["high"], 1)

    def test_failed_scan_exits_2_with_the_reason(self):
        failed = dict(DONE, status="failed", error_code="not_verified")
        code, out, err, _ = self.run_cli(["cloud", "scan", "example.com"],
                                         self.scan_routes([failed]))
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("isn't verified anymore", err)

    def test_unknown_site_exits_2(self):
        code, _, err, calls = self.run_cli(["cloud", "scan", "nope.com"],
                                           self.scan_routes([DONE]))
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("No site 'nope.com'", err)
        self.assertFalse(any(c[0] == "POST" for c in calls))

    def test_missing_config_exits_2(self):
        err = io.StringIO()
        with mock.patch.dict("os.environ", {}, clear=True), redirect_stderr(err):
            code = cli.main(["cloud", "sites"])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("CAULK_API_KEY", err.getvalue())


if __name__ == "__main__":
    unittest.main()
