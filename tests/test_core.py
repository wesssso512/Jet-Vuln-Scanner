"""Unit tests for the non-GUI core. No live network required."""
import unittest
from types import SimpleNamespace

from jetscanner import advisor
from jetscanner.models import Finding, ModuleResult, Severity
from jetscanner.port_scanner import _port_finding
from jetscanner.validators import InvalidTarget, is_valid_target, normalize_target
from jetscanner.web_scanner import WebScanner


class TestValidators(unittest.TestCase):
    def test_plain_domain(self):
        host, url = normalize_target("example.com")
        self.assertEqual(host, "example.com")
        self.assertEqual(url, "http://example.com")

    def test_url_with_query_is_preserved(self):
        # This is the V1 regression: a URL with '?' must be accepted and kept.
        host, url = normalize_target("http://site.com/page?id=1")
        self.assertEqual(host, "site.com")
        self.assertIn("?id=1", url)

    def test_ipv4_and_localhost(self):
        self.assertTrue(is_valid_target("192.168.1.5"))
        self.assertTrue(is_valid_target("localhost"))

    def test_rejects_garbage(self):
        for bad in ["", "   ", "not a host!", "http://", "ftp://x.com"]:
            with self.assertRaises(InvalidTarget):
                normalize_target(bad)

    def test_rejects_shell_metacharacters(self):
        for bad in ["a.com; rm -rf /", "$(whoami).com", "a b.com"]:
            self.assertFalse(is_valid_target(bad))


class TestAdvisor(unittest.TestCase):
    def test_maps_by_key_and_dedupes(self):
        findings = [
            Finding("xss", "x", Severity.HIGH),
            Finding("port_80", "p", Severity.LOW),
            Finding("port_80", "p", Severity.LOW),  # duplicate key
            Finding("unknown_key", "?", Severity.INFO),
        ]
        advice = advisor.advise(findings)
        titles = [t for t, _ in advice]
        self.assertIn("Cross-Site Scripting (XSS)", titles)
        self.assertEqual(titles.count("Port 80 (HTTP) open"), 1)
        self.assertEqual(len(advice), 2)  # unknown key ignored


class TestPortFinding(unittest.TestCase):
    def test_known_ports(self):
        self.assertEqual(_port_finding(21).key, "port_21")
        self.assertEqual(_port_finding(21).severity, Severity.HIGH)

    def test_unknown_port_gets_generic_key(self):
        f = _port_finding(9999)
        self.assertEqual(f.key, "port_9999")
        self.assertEqual(f.severity, Severity.INFO)


class TestSqliHelpers(unittest.TestCase):
    def test_inject_targets_the_right_param(self):
        from urllib.parse import parse_qs, urlparse
        url = "http://x.com/p?id=1&q=2"
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        out = WebScanner._inject_param(parsed, params, "id", "'")
        self.assertIn("id=1%27", out)   # payload URL-encoded onto id
        self.assertIn("q=2", out)       # other param untouched

    def test_match_sql_error(self):
        body = "warning: mysql_fetch_array() ... you have an error in your sql syntax"
        self.assertEqual(WebScanner._match_sql_error(body), "MySQL")
        self.assertIsNone(WebScanner._match_sql_error("all good here"))


class TestWebScannerFlow(unittest.TestCase):
    """Drive the scanners with a fake _get so no real network is used."""

    def _scanner_returning(self, text="", status=200, headers=None):
        web = WebScanner()
        resp = SimpleNamespace(text=text, status_code=status,
                               headers=headers or {})
        web._get = lambda *a, **k: resp  # type: ignore[assignment]
        web._post = lambda *a, **k: resp  # type: ignore[assignment]
        return web

    def test_sqli_no_params(self):
        web = self._scanner_returning()
        res = web.check_sqli("http://x.com/page")
        self.assertEqual(res.findings, [])
        self.assertIn("no query parameters", res.text.lower())

    def test_sqli_detected(self):
        web = self._scanner_returning(
            text="you have an error in your sql syntax near ...")
        res = web.check_sqli("http://x.com/p?id=1")
        self.assertTrue(any(f.key == "sqli" for f in res.findings))
        self.assertEqual(res.findings[0].severity, Severity.CRITICAL)

    def test_fingerprint_apache_wordpress(self):
        web = self._scanner_returning(
            text="<html>wp-content/themes</html>",
            headers={"Server": "Apache/2.4.51"})
        res = web.fingerprint("http://x.com")
        keys = {f.key for f in res.findings}
        self.assertIn("apache", keys)
        self.assertIn("wordpress", keys)


class TestModuleResult(unittest.TestCase):
    def test_text_join(self):
        r = ModuleResult(module="m")
        r.log("a")
        r.log("b")
        self.assertEqual(r.text, "a\nb")


if __name__ == "__main__":
    unittest.main()
