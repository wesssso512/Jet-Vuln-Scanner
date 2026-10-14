"""Web scanning layer: fingerprinting, security headers, SQL injection,
reflected XSS and directory busting.

Improvements in V2.2 (over V2.1):
  * A same-origin :class:`~jetscanner.crawler.Crawler` discovers pages, forms
    and parameterized URLs, so SQLi/XSS no longer need the owner to hand-pick a
    vulnerable deep link — they test what the crawler finds. The crawl is run
    once and shared between modules.
  * A new ``check_headers`` module reports missing security headers and
    insecure cookies. It is passive (a normal browser visit) and returns
    useful results on virtually any real site.
  * SQLi now detects *blind* (boolean-based) injection in addition to
    error-based, so a site that hides its database errors is still caught.
    These are detection probes (tautologies) only — never data-extraction.
  * Reflected XSS is tested in URL query parameters, not only in form fields.

These checks are deliberately simple and educational. They can still produce
false positives/negatives and are not a substitute for professional tooling.
Only scan systems you own or are authorized in writing to test.
"""
from __future__ import annotations

from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from .crawler import CrawlResult, Crawler, form_details
from .models import Finding, ModuleResult, Severity

_DEFAULT_TIMEOUT = 6
_USER_AGENT = "JetVulnScanner/2.2 (+educational; authorized-use-only)"

# -- SQLi detection data --------------------------------------------------
_SQL_ERRORS = {
    "MySQL": ["you have an error in your sql syntax", "warning: mysql",
              "unclosed quotation mark", "mysql_fetch", "mysqli"],
    "SQL Server": ["unclosed quotation mark after the character string",
                   "microsoft ole db provider for sql server",
                   "microsoft odbc", "incorrect syntax near"],
    "Oracle": ["quoted string not properly terminated", "ora-01756",
               "ora-00933", "oracle error"],
    "PostgreSQL": ["syntax error at or near", "unterminated quoted string",
                   "pg_query", "psql:"],
}
# A single quote breaks unparameterized SQL; the error strings above reveal it.
_SQL_ERROR_PROBES = ["'", '"']
# Boolean-based detection: a true tautology should look like the original page;
# a false one should differ. These confirm input reaches SQL *without*
# extracting any data.
_SQL_TRUE = ["' AND '1'='1", " AND 1=1"]
_SQL_FALSE = ["' AND '1'='2", " AND 1=2"]

# -- XSS detection data ---------------------------------------------------
# A unique, non-executing marker. If it comes back inside an HTML tag context
# unescaped, the page reflects input without encoding it.
_XSS_MARKER = "jXsS9Qz1"
_XSS_PROBE = f"<{_XSS_MARKER}>"

_COMMON_DIRS = [
    "admin", "login", "dashboard", "uploads", "images", "css", "js",
    "backup", "db", "config", "portal", "test", "robots.txt",
]

# How many discovered injection points one module will test, to bound a scan.
_MAX_TEST_POINTS = 15
# Boolean-based similarity thresholds (difflib ratio, 0..1).
_SIMILAR = 0.95        # true-condition page ~ original page
_DIFFERENT = 0.90      # false-condition page must drop below this vs original


class WebScanner:
    def __init__(self, timeout: int = _DEFAULT_TIMEOUT,
                 verify_tls: bool = True) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": _USER_AGENT})
        self.session.verify = verify_tls
        # Crawl results memoized per origin so sqli and xss share one crawl.
        self._crawl_cache: Dict[str, CrawlResult] = {}

    # -- low-level requests ----------------------------------------------
    def _get(self, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", self.timeout)
        try:
            return self.session.get(url, **kwargs)
        except requests.RequestException:
            return None

    def _post(self, url: str, data: dict) -> Optional[requests.Response]:
        try:
            return self.session.post(url, data=data, timeout=self.timeout)
        except requests.RequestException:
            return None

    def _discover(self, url: str) -> CrawlResult:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        cached = self._crawl_cache.get(origin)
        if cached is None:
            cached = Crawler(self._get, self.timeout).crawl(url)
            self._crawl_cache[origin] = cached
        return cached

    # -- fingerprint ------------------------------------------------------
    def fingerprint(self, url: str) -> ModuleResult:
        result = ModuleResult(module="Tech Fingerprint")
        result.log(f"[*] Fingerprinting {url} ...")

        response = self._get(url)
        if response is None:
            result.error = "Request failed (host unreachable or timed out)."
            result.log(f"[-] {result.error}")
            return result

        server = response.headers.get("Server")
        if server:
            result.log(f"    [+] Server: {server}")
            if "apache" in server.lower():
                result.add(Finding("apache", "Apache server detected",
                                   Severity.INFO, server))
            if "nginx" in server.lower():
                result.add(Finding("nginx", "nginx server detected",
                                   Severity.INFO, server))

        powered_by = response.headers.get("X-Powered-By")
        if powered_by:
            result.log(f"    [+] X-Powered-By: {powered_by}")

        content = response.text.lower()
        cms_map = {
            "wordpress": ("wp-content", "wordpress"),
            "joomla": ("joomla",),
            "drupal": ("drupal",),
        }
        detected = False
        for cms, needles in cms_map.items():
            if any(n in content for n in needles):
                result.log(f"    [+] CMS: {cms.title()}")
                result.add(Finding(cms, f"{cms.title()} detected", Severity.INFO))
                detected = True
        if not detected:
            result.log("    [?] CMS: not identified (custom or hidden)")
        return result

    # -- security headers (passive) --------------------------------------
    def check_headers(self, url: str) -> ModuleResult:
        """Report missing security headers and insecure cookies.

        Passive: this only reads the response to a normal GET, the same thing
        a browser does. Every finding is a best-practice gap, not proof of a
        break-in, so severities are kept modest.
        """
        result = ModuleResult(module="Security Headers")
        result.log(f"[*] Checking response headers for {url} ...")

        response = self._get(url, allow_redirects=True)
        if response is None:
            result.error = "Request failed (host unreachable or timed out)."
            result.log(f"[-] {result.error}")
            return result

        final = urlparse(response.url)
        is_https = final.scheme == "https"
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Served over plain HTTP and didn't end up on HTTPS.
        if not is_https:
            result.log("[!] Final URL is not HTTPS.")
            result.add(Finding("no_https", "Site is served without HTTPS",
                               Severity.HIGH, response.url))

        checks: List[Tuple[str, str, str, Severity]] = [
            ("strict-transport-security", "missing_hsts",
             "HSTS header missing", Severity.LOW),
            ("content-security-policy", "missing_csp",
             "Content-Security-Policy missing", Severity.LOW),
            ("x-content-type-options", "missing_xcto",
             "X-Content-Type-Options missing", Severity.LOW),
            ("referrer-policy", "missing_referrer_policy",
             "Referrer-Policy missing", Severity.INFO),
        ]
        for header, key, title, sev in checks:
            # HSTS is meaningless over plain HTTP; don't nag about it there.
            if key == "missing_hsts" and not is_https:
                continue
            if header not in headers:
                result.log(f"    [-] Missing: {header}")
                result.add(Finding(key, title, sev, f"header: {header}"))
            else:
                result.log(f"    [+] Present: {header}")

        # Clickjacking protection can come from either header.
        csp = headers.get("content-security-policy", "").lower()
        if "x-frame-options" not in headers and "frame-ancestors" not in csp:
            result.log("    [-] No clickjacking protection "
                       "(X-Frame-Options / frame-ancestors).")
            result.add(Finding("missing_xfo", "Clickjacking protection missing",
                               Severity.MEDIUM, "X-Frame-Options"))

        self._check_cookies(response, result)
        return result

    @staticmethod
    def _check_cookies(response: requests.Response, result: ModuleResult) -> None:
        # Only the unambiguous mistake: a cookie set over HTTPS without the
        # Secure flag can leak to a plain-HTTP request. We deliberately don't
        # flag missing HttpOnly on its own — some cookies are meant to be
        # read by JavaScript, so that check is noisy. One finding is enough.
        if urlparse(response.url).scheme != "https":
            return
        for cookie in response.cookies:
            if not cookie.secure:
                result.log(f"    [-] Cookie '{cookie.name}' missing: Secure")
                result.add(Finding(
                    "insecure_cookie", "Cookie set without the Secure flag",
                    Severity.MEDIUM, f"cookie={cookie.name}"))
                return

    # -- SQL injection ----------------------------------------------------
    def check_sqli(self, url: str) -> ModuleResult:
        result = ModuleResult(module="SQL Injection")
        result.log(f"[*] SQLi scan starting from {url} ...")

        targets = self._param_urls(url)
        if not targets:
            result.log("[-] No parameterized URLs found to test "
                       "(crawled the site and found no ?name=value links).")
            return result

        result.log(f"[*] Testing {len(targets)} parameterized URL(s).")
        seen: set = set()
        for test_url in targets[:_MAX_TEST_POINTS]:
            self._test_url_sqli(test_url, result, seen)
        if not result.findings:
            result.log("[-] No SQL injection detected.")
        return result

    def _test_url_sqli(self, url: str, result: ModuleResult, seen: set) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        baseline = self._get(url)
        base_text = _norm(baseline.text) if baseline is not None else None

        for pname in params:
            sig = (parsed.path, pname)
            if sig in seen:
                continue

            # 1) Error-based: a broken quote surfaces a database error.
            db = None
            for probe in _SQL_ERROR_PROBES:
                resp = self._get(self._inject(parsed, params, pname, probe))
                if resp is not None:
                    db = _match_sql_error(resp.text.lower())
                    if db:
                        break
            if db:
                seen.add(sig)
                result.log(f"[!!!] Error-based SQLi: param '{pname}' ({db}).")
                result.add(Finding("sqli", "SQL injection", Severity.CRITICAL,
                                   f"param={pname} db={db} url={parsed.path}"))
                continue

            # 2) Boolean-based: input changes the query's logic.
            if base_text and self._boolean_sqli(parsed, params, pname, base_text):
                seen.add(sig)
                result.log(f"[!!!] Boolean-based (blind) SQLi: param '{pname}'.")
                result.add(Finding("sqli", "SQL injection", Severity.CRITICAL,
                                   f"param={pname} type=blind url={parsed.path}"))

    def _boolean_sqli(self, parsed, params, pname, base_text: str) -> bool:
        """True when a true/false tautology flips the page's content.

        Requires the true-condition page to resemble the original and the
        false-condition page to differ from both — which an app only does when
        the parameter is interpolated into a SQL ``WHERE`` clause. Pure
        detection: no data is read or changed.
        """
        for truthy, falsy in zip(_SQL_TRUE, _SQL_FALSE):
            t_resp = self._get(self._inject(parsed, params, pname, truthy))
            f_resp = self._get(self._inject(parsed, params, pname, falsy))
            if t_resp is None or f_resp is None:
                continue
            t_text, f_text = _norm(t_resp.text), _norm(f_resp.text)
            true_like_base = _ratio(base_text, t_text) >= _SIMILAR
            false_differs = _ratio(base_text, f_text) < _DIFFERENT
            true_false_differ = _ratio(t_text, f_text) < _DIFFERENT
            if true_like_base and false_differs and true_false_differ:
                return True
        return False

    @staticmethod
    def _inject(parsed, params, target_param, payload) -> str:
        new_params = {k: v[:] for k, v in params.items()}
        original = new_params[target_param][0] if new_params[target_param] else ""
        new_params[target_param] = [original + payload]
        new_query = urlencode(new_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    # -- XSS --------------------------------------------------------------
    def check_xss(self, url: str) -> ModuleResult:
        result = ModuleResult(module="XSS")
        result.log(f"[*] XSS scan starting from {url} ...")

        discovered = self._discover(url)
        seen: set = set()

        # 1) Reflected XSS in URL query parameters.
        param_urls = self._param_urls(url)
        for test_url in param_urls[:_MAX_TEST_POINTS]:
            self._test_param_xss(test_url, result, seen)

        # 2) Reflected XSS in form fields (forms crawled + on the start page).
        forms = list(discovered.forms) or [(url, d) for d in self._page_forms(url)]
        result.log(f"[*] Testing {len(param_urls)} URL param set(s) "
                   f"and {len(forms)} form(s).")
        for page_url, details in forms[:_MAX_TEST_POINTS]:
            self._test_form_xss(page_url, details, result, seen)

        if not result.findings:
            result.log("[-] No reflected XSS detected.")
        return result

    def _test_param_xss(self, url: str, result: ModuleResult, seen: set) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for pname in params:
            sig = ("param", parsed.path, pname)
            if sig in seen:
                continue
            resp = self._get(self._inject(parsed, params, pname, _XSS_PROBE))
            if resp is not None and _XSS_PROBE in resp.text:
                seen.add(sig)
                result.log(f"[!!!] Reflected XSS: param '{pname}' "
                           f"on {parsed.path}.")
                result.add(Finding("xss", "Reflected XSS", Severity.HIGH,
                                   f"param={pname} url={parsed.path}"))

    def _test_form_xss(self, page_url: str, details: dict,
                       result: ModuleResult, seen: set) -> None:
        action = urljoin(page_url, details["action"])
        sig = ("form", action, details["method"])
        if sig in seen:
            return
        data = {
            i["name"]: _XSS_PROBE
            for i in details["inputs"]
            if i["name"] and i["type"] in ("text", "search", "url", "email",
                                           "textarea", "")
        }
        if not data:
            return
        if details["method"] == "post":
            resp = self._post(action, data)
        else:
            resp = self._get(action, params=data)
        if resp is not None and _XSS_PROBE in resp.text:
            seen.add(sig)
            result.log(f"[!!!] Reflected XSS via form action "
                       f"{details['action'] or '(self)'}.")
            result.add(Finding("xss", "Reflected XSS", Severity.HIGH,
                               f"form={details['action'] or '(self)'}"))

    def _page_forms(self, url: str) -> List[dict]:
        response = self._get(url)
        if response is None:
            return []
        soup = BeautifulSoup(response.text, "html.parser")
        return [form_details(f) for f in soup.find_all("form")]

    # -- shared discovery -------------------------------------------------
    def _param_urls(self, url: str) -> List[str]:
        """Parameterized URLs to test: the target itself (if it has a query)
        plus everything the crawler found, de-duplicated by path+param-names."""
        discovered = self._discover(url)
        urls: List[str] = []
        seen: set = set()
        for candidate in [url, *discovered.param_urls]:
            parsed = urlparse(candidate)
            if not parsed.query:
                continue
            names = tuple(sorted(parse_qs(parsed.query, keep_blank_values=True)))
            sig = (parsed.path, names)
            if sig not in seen:
                seen.add(sig)
                urls.append(candidate)
        return urls

    # -- directory busting ------------------------------------------------
    def scan_directories(self, url: str) -> ModuleResult:
        result = ModuleResult(module="Directory Busting")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        result.log(f"[*] Directory busting on {base} ...")

        found = 0
        for path in _COMMON_DIRS:
            response = self._get(urljoin(base, path), allow_redirects=False)
            if response is None:
                continue
            if response.status_code == 200:
                found += 1
                result.log(f"[+] 200 OK   {urljoin(base, path)}")
                result.add(Finding("dir_found", f"Path exposed: /{path}",
                                   Severity.LOW, urljoin(base, path)))
            elif response.status_code == 403:
                found += 1
                result.log(f"[!] 403 Forbidden   {urljoin(base, path)}")

        if not found:
            result.log("[-] No common directories found.")
        return result


# -- module-level helpers -------------------------------------------------
def _match_sql_error(body: str) -> Optional[str]:
    for db, errors in _SQL_ERRORS.items():
        if any(err in body for err in errors):
            return db
    return None


def _norm(text: str) -> str:
    """Collapse whitespace so trivial differences don't fool the ratio."""
    return " ".join(text.split())


def _ratio(a: str, b: str) -> float:
    # Cap the compared length: huge pages make SequenceMatcher slow and the
    # leading content is enough to tell two responses apart.
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()
