"""Jet Vulnerability Scanner — V2.

A small, educational, multi-module security scanner (network + web) with a
Tkinter GUI. The package is intentionally split by responsibility:

    models      -> plain data structures (Finding, ModuleResult, Severity)
    validators  -> target parsing / validation / normalization
    port_scanner-> network layer (socket + optional nmap)
    web_scanner -> web layer (fingerprint, SQLi, XSS, dir busting)
    advisor     -> rule-based knowledge base (findings -> remediation advice)
    reporting   -> text report building + cross-platform file opening
    ui          -> Tkinter GUI (the only module that touches Tk)

Only scan systems you own or have explicit written permission to test.
"""

__version__ = "2.0.0"
