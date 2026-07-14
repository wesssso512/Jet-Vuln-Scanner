"""Network scanning layer: a plain TCP-connect socket scan and an optional
Nmap wrapper.

Fixes vs V1:
  * Nmap is invoked with an argument *list* and ``shell=False`` — no shell
    interpolation, no command-injection surface.
  * ``subprocess.run(..., timeout=)`` instead of an unbounded ``Popen``.
  * Cross-platform nmap discovery via ``shutil.which`` before Windows paths.
  * Returns ``ModuleResult`` with structured ``Finding`` objects instead of
    a formatted string.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from typing import Iterable, Optional

from .models import Finding, ModuleResult, Severity

# Ports we know how to give advice about map to a stable finding key + metadata.
_PORT_INFO = {
    21: ("port_21", "FTP (21) open", Severity.HIGH),
    22: ("port_22", "SSH (22) open", Severity.INFO),
    80: ("port_80", "HTTP (80) open", Severity.LOW),
    443: ("port_443", "HTTPS (443) open", Severity.INFO),
    3306: ("port_3306", "MySQL (3306) open", Severity.MEDIUM),
    8080: ("port_8080", "HTTP-alt (8080) open", Severity.LOW),
}

_DEFAULT_PORTS = tuple(sorted(_PORT_INFO))

# Matches an nmap port row like: "80/tcp open http"
_NMAP_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s*(.*)$")


def _port_finding(port: int) -> Finding:
    key, title, sev = _PORT_INFO.get(
        port, (f"port_{port}", f"Port {port} open", Severity.INFO)
    )
    return Finding(key=key, title=title, severity=sev, detail=f"Port {port}")


class PortScanner:
    """Socket + optional Nmap scanning."""

    def __init__(self) -> None:
        self.nmap_path: Optional[str] = self._locate_nmap()

    @staticmethod
    def _locate_nmap() -> Optional[str]:
        found = shutil.which("nmap")
        if found:
            return found
        for candidate in (
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ):
            if os.path.exists(candidate):
                return candidate
        return None

    # -- socket -----------------------------------------------------------
    def scan_socket(
        self,
        host: str,
        ports: Optional[Iterable[int]] = None,
        timeout: float = 1.0,
    ) -> ModuleResult:
        ports = tuple(ports) if ports is not None else _DEFAULT_PORTS
        result = ModuleResult(module="Socket Scan")
        result.log(f"[*] Socket scan on {host} ...")

        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror as exc:
            result.error = f"DNS resolution failed: {exc}"
            result.log(f"[-] {result.error}")
            return result

        if resolved != host:
            result.log(f"[*] Resolved to {resolved}")

        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((resolved, port)) == 0:
                        result.log(f"[+] Port {port} is OPEN")
                        result.add(_port_finding(port))
            except OSError:
                continue

        if not result.findings:
            result.log("[-] No common open ports found.")
        result.log("[*] Socket scan complete.")
        return result

    # -- nmap -------------------------------------------------------------
    def scan_nmap(self, host: str, timeout: int = 120) -> ModuleResult:
        result = ModuleResult(module="Nmap Scan")

        if not self.nmap_path:
            result.error = "Nmap not found on this system."
            result.log(f"[-] {result.error} (install it or use the Socket scan)")
            return result

        result.log(f"[*] Nmap scan on {host} ...")
        cmd = [
            self.nmap_path,
            "-Pn", "-F", "-sV",
            "--version-intensity", "0",
            "-T4",
            host,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            result.error = "Nmap scan timed out."
            result.log(f"[-] {result.error}")
            return result
        except OSError as exc:
            result.error = f"Failed to execute nmap: {exc}"
            result.log(f"[-] {result.error}")
            return result

        self._parse_nmap_output(proc.stdout, proc.stderr, result)
        return result

    @staticmethod
    def _parse_nmap_output(stdout: str, stderr: str, result: ModuleResult) -> None:
        found_row = False
        for raw in (stdout or "").splitlines():
            line = raw.strip()
            match = _NMAP_PORT_RE.match(line)
            if match:
                found_row = True
                port = int(match.group(1))
                state = match.group(3).lower()
                service = match.group(4).strip()
                result.log(f"[+] {line}")
                if state == "open":
                    finding = _port_finding(port)
                    if service:
                        finding.detail = f"Port {port} — {service}"
                    result.add(finding)
            elif line.startswith(("Service Info:", "Running:", "OS details:")):
                result.log(f"    {line}")

        if not found_row:
            trimmed = (stdout or "").strip()
            if trimmed:
                result.log(trimmed)
            elif stderr:
                result.log(f"[!] Nmap: {stderr.strip()}")
            else:
                result.log("[-] No output returned from Nmap.")
