"""Web scanning layer: fingerprinting, SQL injection, reflected XSS and
directory busting.

Fixes vs V1:
  * One shared ``requests.Session`` with a real User-Agent and a default
    timeout on *every* request (V1 had unbounded requests that could hang).
  * SQLi injects into each query parameter individually and rebuilds the URL
    correctly, instead of blindly appending the payload to the whole URL.
  * No bare ``except:``; network errors are caught narrowly.
  * Structured ``Finding`` output so the advisor never has to parse text.

These checks are deliberately simple and educational. They produce false
positives/negatives and are not a substitute for real tooling.
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from .models import Finding, ModuleResult, Severity

_DEFAULT_TIMEOUT = 6
_USER_AGENT = "JetVulnScanner/2.0 (+educational; authorized-use-only)"

_SQL_ERRORS = {
    "MySQL": ["you have an error in your sql syntax", "warning: mysql",
              "unclosed quotation mark"],
    "SQL Server": ["unclosed quotation mark after the character string",
                   "microsoft ole db provider for sql server"],
    "Oracle": ["quoted string not properly terminated", "ora-01756", "oracle error"],
    "PostgreSQL": ["syntax error at or near", "unterminated quoted string"],
}
_SQL_PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1']
_XSS_PAYLOAD = "<script>alert('JetXSS')</script>"
_COMMON_DIRS = [
    "admin", "login", "dashboard", "uploads", "images", "css", "js",
    "backup", "db", "config", "portal", "test", "robots.txt",
]


class WebScanner:
    def __init__(self, timeout: int = _DEFAULT_TIMEOUT,
                 verify_tls: bool = True) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": _USER_AGENT})
        self.session.verify = verify_tls

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

    # -- SQL injection ----------------------------------------------------
    def check_sqli(self, url: str) -> ModuleResult:
        result = ModuleResult(module="SQL Injection")
        result.log(f"[*] SQLi scan on {url} ...")

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            result.log("[-] URL has no query parameters to test "
                       "(e.g. try http://site/page?id=1).")
            return result

        for pname in params:
            for payload in _SQL_PAYLOADS:
                test_url = self._inject_param(parsed, params, pname, payload)
                response = self._get(test_url)
                if response is None:
                    continue
                db = self._match_sql_error(response.text.lower())
                if db:
                    result.log("[!!!] Possible SQL injection found!")
                    result.log(f"    [+] Parameter: {pname}")
                    result.log(f"    [+] Database: {db}")
                    result.log(f"    [+] Payload: {payload}")
                    result.add(Finding(
                        "sqli", "SQL injection", Severity.CRITICAL,
                        f"param={pname} db={db}",
                    ))
                    return result

        result.log("[-] No error-based SQL injection detected.")
        return result

    @staticmethod
    def _inject_param(parsed, params, target_param, payload) -> str:
        new_params = {k: v[:] for k, v in params.items()}
        original = new_params[target_param][0] if new_params[target_param] else ""
        new_params[target_param] = [original + payload]
        new_query = urlencode(new_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _match_sql_error(body: str) -> Optional[str]:
        for db, errors in _SQL_ERRORS.items():
            if any(err in body for err in errors):
                return db
        return None

    # -- XSS --------------------------------------------------------------
    def check_xss(self, url: str) -> ModuleResult:
        result = ModuleResult(module="XSS")
        result.log(f"[*] XSS scan on {url} ...")

        forms = self._get_forms(url)
        result.log(f"[*] Found {len(forms)} form(s).")
        if not forms:
            result.log("[-] No forms to test.")
            return result

        for form in forms:
            details = self._form_details(form)
            response = self._submit_form(url, details, _XSS_PAYLOAD)
            if response is not None and _XSS_PAYLOAD in response.text:
                result.log("[!!!] Reflected XSS found!")
                result.log(f"    [+] Form action: {details['action'] or '(self)'}")
                result.add(Finding(
                    "xss", "Reflected XSS", Severity.HIGH,
                    f"action={details['action'] or '(self)'}",
                ))
                return result

        result.log("[-] No reflected XSS detected.")
        return result

    def _get_forms(self, url: str):
        response = self._get(url)
        if response is None:
            return []
        return BeautifulSoup(response.text, "html.parser").find_all("form")

    @staticmethod
    def _form_details(form) -> dict:
        inputs = []
        for tag in form.find_all("input"):
            inputs.append({
                "type": tag.attrs.get("type", "text"),
                "name": tag.attrs.get("name"),
            })
        return {
            "action": form.attrs.get("action", "") or "",
            "method": form.attrs.get("method", "get").lower(),
            "inputs": inputs,
        }

    def _submit_form(self, url, details, value):
        target = urljoin(url, details["action"])
        data = {
            i["name"]: value
            for i in details["inputs"]
            if i["name"] and i["type"] in ("text", "search", "url", "email")
        }
        if not data:
            return None
        if details["method"] == "post":
            return self._post(target, data)
        return self._get(target, params=data)

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
