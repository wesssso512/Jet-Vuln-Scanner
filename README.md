<div align="center">

# 🛡️ Jet Vulnerability Scanner — V2

**A small, modular desktop security tool for network & web vulnerability assessment.**

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20macOS%20|%20Linux-0078D6?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> ⚠️ **Educational & authorized use only.** Only scan systems you own or have explicit written permission to test.

</div>

---

## 📖 Overview

Jet Vulnerability Scanner is a desktop app with a Tkinter GUI that runs several
basic network- and web-level checks from one place. **V2** is a full rewrite of
V1 focused on correctness, thread-safety, and a cleaner architecture.

The scanning modules are intentionally simple and educational. They are **not**
a replacement for mature tools like Nmap, Nikto, sqlmap or OWASP ZAP, and they
produce false positives and false negatives by design.

---

## ✨ Modules

| Module | What it does |
|---|---|
| 🔌 **Socket Scan** | TCP-connect scan across common ports (21, 22, 80, 443, 3306, 8080) |
| 🗺️ **Nmap Scan** | Optional wrapper around Nmap (`-Pn -F -sV`), invoked safely with no shell |
| 🧬 **Tech Fingerprint** | Reads `Server` / `X-Powered-By` headers and detects WordPress / Joomla / Drupal |
| 💉 **SQL Injection** | Error-based test that injects into each query parameter individually |
| 🖥️ **XSS** | Reflected XSS check against discovered HTML forms |
| 📂 **Directory Busting** | Requests a short list of common paths and reports 200 / 403 |
| 🧭 **Security Advisor** | **Rule-based** table that maps findings → remediation advice (not AI/ML) |
| 💾 **Report Export** | Writes scan logs + advisor output to a timestamped file in `reports/` |

---

## 🏗️ Architecture

V2 separates responsibilities by layer. Scanners return **structured data**
(`Finding` objects), and the UI, advisor and report all consume that same data —
nothing scrapes the on-screen text box to recover results.

```
Jet-Vuln-Scanner/
├── main.py                  # thin entry point → launches the GUI
├── jetscanner/
│   ├── models.py            # Finding / ModuleResult / Severity data classes
│   ├── validators.py        # target parsing, validation & normalization
│   ├── port_scanner.py      # socket + optional nmap (shell-free)
│   ├── web_scanner.py       # fingerprint, SQLi, XSS, dir busting
│   ├── advisor.py           # rule-based knowledge base (key → advice)
│   ├── reporting.py         # report building + cross-platform file open
│   └── ui.py                # Tkinter GUI (the only Tk-aware module)
├── tests/
│   └── test_core.py         # unit tests for the non-GUI core
├── requirements.txt
├── .gitignore
└── README.md
```

**Data flow:**

```
Target → validators.normalize_target() → (host, url)
                                            │
              ┌─────────────────────────────┴───────────────────────┐
              ▼                                                       ▼
      PortScanner (socket / nmap)                        WebScanner (http)
              └──────────────► List[Finding] ◄───────────────────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                 ▼
              advisor.advise   ui rendering    reporting.build_report
```

---

## 🚀 Installation & Usage

### Prerequisites
- Python 3.9+
- Tkinter (bundled with most Python installers; on Debian/Ubuntu: `sudo apt install python3-tk`)
- [Nmap](https://nmap.org/download.html) — optional, only for the Nmap module

### Steps
```bash
git clone https://github.com/wesssso512/Jet-Vuln-Scanner.git
cd Jet-Vuln-Scanner
pip install -r requirements.txt
python main.py
```

### Running the tests
```bash
python -m unittest discover -s tests -t .
```

---

## ⚠️ Known limitations

- **SQLi** is error-based only; it won't catch blind/time-based injection.
- **XSS** checks reflected payloads in forms only, with no DOM/context awareness.
- **Directory busting** uses a tiny built-in wordlist.
- These checks are for learning; verify anything important with dedicated tools.

---

## ⚖️ Legal disclaimer

For educational purposes and authorized testing only. Unauthorized scanning of
systems you do not own or have permission to test is **illegal** and
**unethical**. The author assumes no liability for misuse.

---

## 👨‍💻 Author

**Owais Boshnak** — Information Engineering, Syrian Virtual University (SVU)
[GitHub](https://github.com/wesssso512)

---

<div align="center">

**⭐ If this was useful, consider starring the repository.**

</div>
