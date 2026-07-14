"""Target parsing, validation and normalization.

V1 bug this fixes: the old validator stripped every ``/`` and rejected any URL
containing ``?``. That made it impossible to submit a parameterized URL, which
in turn made the SQL-injection module (that *requires* a query string)
completely unreachable from the GUI.

Here we parse the target properly, validate the *host* only, and keep the full
URL intact (path + query) for the web modules.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Tuple
from urllib.parse import urlparse

# A single DNS label: 1-63 chars, alphanumeric or hyphen, not starting/ending
# with a hyphen. The full host is one-or-more labels plus a TLD of 2+ letters.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)" + _LABEL + r"(\." + _LABEL + r")*\.[A-Za-z]{2,63}$"
)


class InvalidTarget(ValueError):
    """Raised when a target cannot be parsed into a valid host."""


def _is_valid_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(host)  # accepts IPv4 and IPv6
        return True
    except ValueError:
        pass
    return bool(_DOMAIN_RE.match(host))


def normalize_target(raw: str) -> Tuple[str, str]:
    """Validate ``raw`` and return ``(host, url)``.

    ``host`` is the bare hostname/IP (for socket/nmap scans). ``url`` is a full
    HTTP(S) URL preserving any path/query the user supplied (for web scans).

    Raises :class:`InvalidTarget` on anything that is not a valid IP or domain.
    """
    if raw is None:
        raise InvalidTarget("Target cannot be empty.")
    raw = raw.strip()
    if not raw:
        raise InvalidTarget("Target cannot be empty.")

    has_scheme = "://" in raw
    parse_src = raw if has_scheme else "http://" + raw
    parsed = urlparse(parse_src)

    if parsed.scheme not in ("http", "https"):
        raise InvalidTarget("Only http:// and https:// targets are supported.")

    host = parsed.hostname
    if not host:
        raise InvalidTarget("Could not extract a host from the target.")
    if not _is_valid_host(host):
        raise InvalidTarget(
            "Target host is not a valid IP or domain.\n"
            "Examples: example.com, 192.168.1.5, localhost, "
            "http://site.com/page?id=1"
        )

    url = raw if has_scheme else "http://" + raw
    return host, url


def is_valid_target(raw: str) -> bool:
    """Boolean convenience wrapper around :func:`normalize_target`."""
    try:
        normalize_target(raw)
        return True
    except InvalidTarget:
        return False
