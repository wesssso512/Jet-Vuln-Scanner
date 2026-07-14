"""Rule-based security advisor.

V1 recovered advice by scraping the log text box for substrings like
``"Port 80"`` and ``"open"`` — which broke on casing (``OPEN`` vs ``open``) and
was generally fragile. Here advice is looked up directly by a ``Finding.key``,
so the knowledge base and the scanners share one vocabulary.

Note: this is a static rule table, not machine learning. It is labelled a
"security advisor", not "AI".
"""
from __future__ import annotations

from typing import Iterable, List, Tuple

from .models import Finding

Advice = Tuple[str, str]  # (title, body)

KNOWLEDGE_BASE: dict = {
    "xss": (
        "Cross-Site Scripting (XSS)",
        "- Meaning: attacker-controlled scripts run in other users' browsers.\n"
        "- Risk: session hijacking, defacement, credential theft.\n"
        "- Fix: output-encode all user data and set a Content-Security-Policy.",
    ),
    "sqli": (
        "SQL Injection (SQLi)",
        "- Meaning: user input is interpreted as SQL by the database.\n"
        "- Risk: data theft, tampering, full database compromise.\n"
        "- Fix: use parameterized queries / prepared statements everywhere.",
    ),
    "port_80": (
        "Port 80 (HTTP) open",
        "- Meaning: unencrypted web traffic is served.\n"
        "- Risk: traffic can be sniffed or modified in transit.\n"
        "- Fix: redirect to HTTPS (443) and enable HSTS.",
    ),
    "port_21": (
        "Port 21 (FTP) open",
        "- Meaning: FTP is active and sends credentials in clear text.\n"
        "- Risk: passwords are trivially captured on the wire.\n"
        "- Fix: disable FTP; use SFTP/FTPS instead.",
    ),
    "port_22": (
        "Port 22 (SSH) open",
        "- Advice: disable root login and password auth; use key-based auth "
        "and consider rate-limiting / fail2ban.",
    ),
    "port_3306": (
        "Port 3306 (MySQL) exposed",
        "- Risk: a database port reachable from the network is a common breach "
        "vector.\n- Fix: bind MySQL to localhost or restrict via firewall/VPN.",
    ),
    "wordpress": (
        "WordPress detected",
        "- Risk: outdated plugins/themes are a frequent attack vector.\n"
        "- Fix: keep core, themes and plugins patched; protect wp-login.",
    ),
    "apache": (
        "Apache server detected",
        "- Advice: hide version banners (ServerTokens Prod / ServerSignature Off).",
    ),
    "nginx": (
        "nginx server detected",
        "- Advice: hide version banners (server_tokens off;).",
    ),
    "dir_found": (
        "Exposed path found",
        "- Risk: admin/backup/config paths may leak data or widen the attack "
        "surface.\n- Fix: restrict access, remove backups, require auth.",
    ),
}


def advise(findings: Iterable[Finding]) -> List[Advice]:
    """Map findings to a de-duplicated, ordered list of advice entries."""
    seen = set()
    out: List[Advice] = []
    for finding in findings:
        entry = KNOWLEDGE_BASE.get(finding.key)
        if entry and finding.key not in seen:
            seen.add(finding.key)
            out.append(entry)
    return out
