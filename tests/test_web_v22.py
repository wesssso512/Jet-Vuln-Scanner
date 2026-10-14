"""Tests for the V2.2 web-scanner additions: the crawler, the security-headers
module, blind (boolean-based) SQLi and reflected XSS in URL parameters.

No real network is used — a tiny in-memory site is served through a fake
fetch function with the same shape as ``requests.Response``.
"""
import unittest
from types import SimpleNamespace

from jetscanner.crawler import Crawler
from jetscanner.models import Severity
from jetscanner.web_scanner import WebScanner


def resp(text="", status=200, headers=None, url="http://x.com/",
         cookies=None):
    return SimpleNamespace(text=text, status_code=status,
                           headers=headers or {}, url=url,
                           cookies=cookies or [])


class FakeSite:
    """Maps a URL -> response. Missing URLs return a 404."""

    def __init__(self, pages):
        self.pages = pages
        self.hits = []

    def fetch(self, url, **kwargs):
        self.hits.append(url)
        page = self.pages.get(url)
        if page is None:
            return resp("not found", status=404, url=url)
        return page


class TestCrawler(unittest.TestCase):
    def test_collects_links_forms_and_param_urls_same_host_only(self):
        site = FakeSite({
            "http://x.com/": resp(
                '<a href="/p?id=1">one</a>'
                '<a href="/about">about</a>'
                '<a href="http://evil.com/x?q=1">off</a>'
                '<form action="/search" method="get">'
                '<input name="q" type="text"></form>',
                headers={"Content-Type": "text/html"}, url="http://x.com/"),
            "http://x.com/p?id=1": resp("<html>item</html>",
                                        headers={"Content-Type": "text/html"},
                                        url="http://x.com/p?id=1"),
            "http://x.com/about": resp("<html>about</html>",
                                       headers={"Content-Type": "text/html"},
                                       url="http://x.com/about"),
        })
        result = Crawler(site.fetch, timeout=5).crawl("http://x.com/")
        param_paths = [u for u in result.param_urls]
        self.assertTrue(any("/p?id=1" in u for u in param_paths))
        self.assertFalse(any("evil.com" in u for u in param_paths))
        self.assertEqual(len(result.forms), 1)
        self.assertIn("http://x.com/about", result.pages)

    def test_page_cap_is_honored(self):
        pages = {f"http://x.com/{i}": resp(
            f'<a href="/{i + 1}">n</a>',
            headers={"Content-Type": "text/html"},
            url=f"http://x.com/{i}") for i in range(100)}
        start = "http://x.com/0"
        result = Crawler(site_fetch(pages), timeout=5,
                         max_pages=5, max_depth=50).crawl(start)
        self.assertLessEqual(len(result.pages), 5)


def site_fetch(pages):
    return FakeSite(pages).fetch


class TestHeaders(unittest.TestCase):
    def _run(self, headers, url="https://x.com/", cookies=None):
        web = WebScanner()
        web._get = lambda *a, **k: resp(  # type: ignore[assignment]
            "<html></html>", headers=headers, url=url, cookies=cookies or [])
        return {f.key for f in web.check_headers(url).findings}

    def test_flags_missing_headers_on_https(self):
        keys = self._run({})
        self.assertIn("missing_hsts", keys)
        self.assertIn("missing_csp", keys)
        self.assertIn("missing_xcto", keys)
        self.assertIn("missing_xfo", keys)
        self.assertNotIn("no_https", keys)

    def test_no_hsts_nag_over_plain_http(self):
        keys = self._run({}, url="http://x.com/")
        self.assertIn("no_https", keys)
        self.assertNotIn("missing_hsts", keys)

    def test_good_headers_produce_no_findings(self):
        keys = self._run({
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
        })
        self.assertEqual(keys, set())

    def test_frame_ancestors_satisfies_clickjacking(self):
        keys = self._run({
            "Content-Security-Policy": "frame-ancestors 'none'",
        })
        self.assertNotIn("missing_xfo", keys)


class TestBlindSqli(unittest.TestCase):
    def test_boolean_based_detection(self):
        # A fake app whose page content depends on a true/false SQL condition.
        base = "<html>" + ("item " * 200) + "</html>"
        false_page = "<html>no results</html>"

        def fetch(url, **kwargs):
            # A real app sees the decoded value; a false condition empties it.
            value = _reflected_value(url.replace("id=", "q="))
            if "1=2" in value or "'1'='2" in value:
                return resp(false_page, url=url)
            return resp(base, url=url)   # original + any true condition

        web = WebScanner()
        web._get = fetch  # type: ignore[assignment]
        res = web.check_sqli("http://x.com/p?id=1")
        self.assertTrue(any(f.key == "sqli" for f in res.findings))
        self.assertEqual(res.findings[0].severity, Severity.CRITICAL)

    def test_stable_site_is_not_flagged(self):
        # Same response regardless of input -> no injection inferred.
        web = WebScanner()
        web._get = lambda *a, **k: resp("<html>always the same</html>")
        res = web.check_sqli("http://x.com/p?id=1")
        self.assertEqual(res.findings, [])


def _reflected_value(url):
    """The decoded 'q' parameter value, as a real app would read it."""
    from urllib.parse import parse_qs, urlparse
    return parse_qs(urlparse(url).query).get("q", [""])[0]


class TestParamXss(unittest.TestCase):
    def test_reflected_in_query_param(self):
        def fetch(url, **kwargs):
            # A vulnerable app reflects the decoded value unescaped.
            return resp(f"<html>you searched {_reflected_value(url)}</html>",
                        url=url)

        web = WebScanner()
        web._get = fetch  # type: ignore[assignment]
        res = web.check_xss("http://x.com/s?q=hello")
        self.assertTrue(any(f.key == "xss" for f in res.findings))
        self.assertEqual(res.findings[0].severity, Severity.HIGH)

    def test_encoded_reflection_is_not_flagged(self):
        from html import escape

        def fetch(url, **kwargs):
            # A safe app HTML-escapes the value, so the raw probe never appears.
            return resp(f"<html>{escape(_reflected_value(url))}</html>", url=url)

        web = WebScanner()
        web._get = fetch  # type: ignore[assignment]
        res = web.check_xss("http://x.com/s?q=hello")
        self.assertEqual([f for f in res.findings if f.key == "xss"], [])


if __name__ == "__main__":
    unittest.main()
