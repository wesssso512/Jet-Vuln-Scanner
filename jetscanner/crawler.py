"""A small, polite, same-origin crawler.

The web modules in V1/V2.1 only ever looked at the single URL the user typed.
On a real site's home page that means the SQLi module finds no query
parameters and the XSS module finds only the forms on that one page, so an
owner whose site *is* vulnerable deeper in usually saw "nothing found". This
crawler walks a bounded number of same-host pages and collects the two things
the active modules need:

    * ``param_urls`` — URLs that carry a query string (SQLi / reflected XSS),
    * ``forms``      — (page_url, form-details) pairs (XSS / form SQLi).

It is deliberately conservative: same host only, http(s) only, a hard page
cap, a shallow depth, and it never submits forms or follows anything but
``<a href>`` links. Discovery only — it sends no payloads.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# A function that fetches a URL and returns the response, or None on failure.
# The web scanner passes its own ``_get`` so the crawler shares the same
# session, timeout and (in tests) the same stub — it never opens its own.
Fetch = Callable[..., Optional["requests.Response"]]

# Keep a scan quick and gentle on the target. These are the safe defaults the
# engine uses; callers may lower them but there is rarely a reason to raise.
_MAX_PAGES = 25
_MAX_DEPTH = 2

# We only crawl things a browser would render as a page.
_HTML_TYPES = ("text/html", "application/xhtml+xml")

# Never follow links that obviously aren't navigable HTML or that could log the
# owner out / trigger an action just by being fetched.
_SKIP_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".pdf",
    ".zip", ".gz", ".tar", ".mp4", ".mp3", ".css", ".js", ".json", ".xml",
    ".woff", ".woff2", ".ttf", ".eot",
)
_SKIP_HINTS = ("logout", "signout", "sign-out", "delete", "remove")


def form_details(form) -> dict:
    """Normalize a BeautifulSoup ``<form>`` into a plain dict.

    Shared with the web scanner so a crawled form and a directly-fetched form
    look identical to the modules that test them.
    """
    inputs = []
    for tag in form.find_all(("input", "textarea")):
        inputs.append({
            "type": (tag.attrs.get("type") or "text").lower(),
            "name": tag.attrs.get("name"),
            "value": tag.attrs.get("value", ""),
        })
    return {
        "action": form.attrs.get("action", "") or "",
        "method": (form.attrs.get("method") or "get").lower(),
        "inputs": inputs,
    }


@dataclass
class CrawlResult:
    """Everything discovery found, de-duplicated and ready for the modules."""

    pages: List[str] = field(default_factory=list)
    param_urls: List[str] = field(default_factory=list)
    forms: List[Tuple[str, dict]] = field(default_factory=list)


class Crawler:
    def __init__(self, fetch: Fetch, timeout: int,
                 max_pages: int = _MAX_PAGES, max_depth: int = _MAX_DEPTH) -> None:
        self.fetch = fetch
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth

    def crawl(self, start_url: str) -> CrawlResult:
        start_host = urlparse(start_url).netloc
        result = CrawlResult()
        seen_pages = set()
        seen_forms = set()          # (action, method, input-name tuple) dedupe
        seen_param_sigs = set()     # (path, sorted param names) dedupe

        queue: deque = deque([(start_url, 0)])
        queued = {urldefrag(start_url)[0]}

        while queue and len(seen_pages) < self.max_pages:
            url, depth = queue.popleft()
            response = self._get(url)
            if response is None or not self._is_html(response):
                continue
            seen_pages.add(url)
            result.pages.append(url)

            final_url = getattr(response, "url", url) or url
            soup = BeautifulSoup(response.text, "html.parser")
            self._collect_forms(url, soup, result, seen_forms)
            self._collect_param_url(final_url, result, seen_param_sigs)

            if depth >= self.max_depth:
                continue
            for link in self._links(url, soup, start_host):
                self._collect_param_url(link, result, seen_param_sigs)
                clean = urldefrag(link)[0]
                if clean not in queued:
                    queued.add(clean)
                    queue.append((link, depth + 1))

        return result

    # -- helpers ----------------------------------------------------------
    def _get(self, url: str) -> Optional[requests.Response]:
        return self.fetch(url, timeout=self.timeout)

    @staticmethod
    def _is_html(response: requests.Response) -> bool:
        ctype = response.headers.get("Content-Type", "")
        return any(t in ctype for t in _HTML_TYPES) or not ctype

    def _links(self, base_url: str, soup, start_host: str) -> List[str]:
        out: List[str] = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            if parsed.netloc != start_host:
                continue
            path = parsed.path.lower()
            if path.endswith(_SKIP_SUFFIXES):
                continue
            if any(h in absolute.lower() for h in _SKIP_HINTS):
                continue
            out.append(absolute)
        return out

    def _collect_param_url(self, url: str, result: CrawlResult,
                           seen: set) -> None:
        parsed = urlparse(url)
        if not parsed.query:
            return
        names = tuple(sorted(
            p.split("=", 1)[0] for p in parsed.query.split("&") if p))
        sig = (parsed.path, names)
        if sig in seen:
            return
        seen.add(sig)
        result.param_urls.append(url)

    def _collect_forms(self, page_url: str, soup, result: CrawlResult,
                       seen: set) -> None:
        for form in soup.find_all("form"):
            details = form_details(form)
            names = tuple(sorted(
                i["name"] for i in details["inputs"] if i["name"]))
            sig = (urljoin(page_url, details["action"]), details["method"], names)
            if sig in seen:
                continue
            seen.add(sig)
            result.forms.append((page_url, details))
