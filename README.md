<div align="center">

# 🛡️ Jet Vulnerability Scanner — V2

**A modular security tool for network & web vulnerability assessment — CLI, Python library, and desktop GUI.**

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20macOS%20|%20Linux-0078D6?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-50%20passing-4bb543?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> ⚠️ **Educational & authorized use only.** Only scan systems you own or have explicit written permission to test.

</div>

---

## 📖 Overview

Jet Vulnerability Scanner runs several network- and web-level security checks
from one place. The scanning engine is a headless Python library; on top of it
sit the `jet` command-line tool (text, JSON, or SARIF output) and a Tkinter
desktop GUI.

**V2 is a full rewrite of V1.** The focus was correctness, thread-safety,
security, and a clean layered architecture — not new features for their own
sake. The scanning checks are intentionally simple and educational; they are
**not** a replacement for mature tools like Nmap, Nikto, sqlmap, or OWASP ZAP,
and they produce false positives and false negatives by design.

---

## 🧠 The core idea behind V2

In V1, every scanner returned a **pre-formatted string**. The UI printed it, and
the advisor tried to recover results by searching that printed text for
keywords. That single design choice caused most of V1's bugs.

In V2, every scanner returns **structured data** — `Finding` objects with a
stable `key`, a `severity`, and details. The UI formats them for display, the
advisor looks them up by `key`, and the report consumes the same data. Nothing
scrapes the screen to recover what was found.

```
Target → validators.normalize_target() → (host, url)
                                            │
              ┌─────────────────────────────┴──────────────────────┐
              ▼                                                      ▼
      PortScanner (socket / nmap)                        WebScanner (http)
              └──────────────► List[Finding] ◄──────────────────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                 ▼
              advisor.advise   UI rendering    reporting.build_report
```

---

## ✨ Modules

| Module | What it does |
|---|---|
| 🔌 **Socket Scan** | TCP-connect scan across common ports (21, 22, 80, 443, 3306, 8080) |
| 🗺️ **Nmap Scan** | Optional Nmap wrapper (`-Pn -F -sV`), invoked safely with no shell |
| 🧬 **Tech Fingerprint** | Reads `Server` / `X-Powered-By` headers, detects WordPress / Joomla / Drupal |
| 💉 **SQL Injection** | Error-based test that injects into each query parameter individually |
| 🖥️ **XSS** | Reflected XSS check against discovered HTML forms |
| 📂 **Directory Busting** | Requests common paths and reports `200` / `403` |
| 🧭 **Security Advisor** | **Rule-based** table mapping findings → remediation advice (not AI/ML) |
| 💾 **Report Export** | Writes scan logs + advisor output to a timestamped file in `reports/` |

---

## 🏗️ Architecture

V2 splits responsibilities by layer instead of cramming everything into one file.

```
Jet-Vuln-Scanner/
├── main.py                  # thin entry point → launches the GUI
├── pyproject.toml           # package metadata + the `jet` command
├── jetscanner/
│   ├── engine.py            # headless orchestration: run_scan() + module registry
│   ├── export.py            # JSON + SARIF 2.1.0 output
│   ├── cli.py               # `jet` command-line interface
│   ├── models.py            # Finding / ModuleResult / ScanReport / Severity
│   ├── validators.py        # target parsing, validation & normalization
│   ├── port_scanner.py      # socket + optional nmap (shell-free)
│   ├── web_scanner.py       # fingerprint, SQLi, XSS, dir busting
│   ├── advisor.py           # rule-based knowledge base (key → advice)
│   ├── reporting.py         # text report building + cross-platform file open
│   └── ui.py                # Tkinter GUI (the only Tk-aware module)
├── tests/                   # 50 unit tests, no live network needed
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🔧 What changed from V1 → V2

| # | Area | V1 problem | V2 fix |
|---|---|---|---|
| 1 | **Structure** | `main.py` was a 441-line "god file" (UI + logic + reporting + knowledge base) driven by globals | Split into a `jetscanner/` package by layer; UI is a class, no globals |
| 2 | **Thread-safety** | Worker thread updated Tkinter widgets directly (Tk is **not** thread-safe → intermittent freezes/crashes) | All UI updates marshalled to the main thread via `root.after(...)` |
| 3 | **Target validation** | Stripped every `/` and rejected any URL with `?`, which made the **SQLi module unreachable** | Parse with `urlparse`, validate the host only, keep the full URL intact |
| 4 | **Command safety** | Nmap run via `shell=True` with an interpolated string (command-injection surface, no timeout) | Argument **list** + `shell=False` + `subprocess.run(..., timeout=)` |
| 5 | **Advisor** | Scraped the log text box for keywords; broke on casing (`OPEN` vs `open`) | Looks advice up by `Finding.key`; scanners & advisor share one vocabulary |
| 6 | **Networking** | Bare `except:` everywhere; some requests had **no timeout** (could hang forever) | Shared `requests.Session`, timeout on every request, narrow exception handling |
| 7 | **SQLi** | Appended the payload to the whole URL | Injects into each query parameter individually and rebuilds the URL correctly |
| 8 | **Ignore file** | File was named `gitignore` (no dot) — git ignored nothing | Renamed to `.gitignore` |
| 9 | **Reporting** | Saved to CWD; opened files Windows-only (`os.startfile`, `explorer`) | Saves to `reports/`; opens on Windows/macOS/Linux |
| 10 | **Tests** | None | 14 unit tests covering validation, advisor, SQLi, nmap parsing, reporting |

---

## 🚀 Installation & Usage

### Prerequisites
- Python 3.9+
- Tkinter (bundled with most Python installers; Debian/Ubuntu: `sudo apt install python3-tk`)
- [Nmap](https://nmap.org/download.html) — optional, only for the Nmap module

### Steps
```bash
git clone https://github.com/wesssso512/Jet-Vuln-Scanner.git
cd Jet-Vuln-Scanner
git checkout V2
pip install -r requirements.txt
python main.py
```

### Command line
Install the package to get the `jet` command (or use `python -m jetscanner`
without installing):
```bash
pip install -e .

jet modules                                        # list modules
jet scan example.com --modules tech,dir            # human-readable report
jet scan example.com -m all -f json | jq .summary  # JSON on stdout
jet scan example.com -m all -f sarif -o jet.sarif  # SARIF 2.1.0 file
jet scan example.com -m all --fail-on high         # exit 1 on high/critical (CI)
```
Results go to stdout (or `--output`); progress and errors go to stderr.
Exit codes: `0` scan completed · `1` a finding met `--fail-on` · `2` usage or
I/O error · `130` interrupted.

#### Cloud scans (`jet cloud`)
Run the scan on the hosted platform instead of your machine: it checks that
you own the site, keeps a history, and works the same way in CI.

```bash
export CAULK_API_KEY=ck_live_...          # dashboard → Settings → API keys
export CAULK_API_URL=https://...          # the platform's API address

jet cloud sites                                         # your sites
jet cloud scan example.com --checks quick               # what any visitor can see
jet cloud scan example.com -f sarif -o caulk.sarif --fail-on high
```

The key is read from the environment only, never from a flag, so it stays
out of shell history. Output formats, `--fail-on` and exit codes match
`jet scan`. See [docs/github-actions.md](docs/github-actions.md) for a
ready-made GitHub Actions workflow that puts findings in the Security tab.

As a library:
```python
from jetscanner import run_scan, to_json

report = run_scan("example.com", ["tech", "dir"])
print(to_json(report))
```

### Docker
The image bundles the engine, the `jet` CLI and Nmap, and runs as a non-root user:
```bash
docker build -t jetscanner .
docker run --rm jetscanner modules
docker run --rm jetscanner scan example.com -m all -f json > report.json
```
- Inside the container, `localhost` is the container itself. To scan something
  running on your machine, use `host.docker.internal` instead.
- To save a report, redirect stdout as above rather than mounting a volume —
  the container's user is not root and may not be able to write to it.

### Running the tests
```bash
python -m unittest discover -s tests -t .
```

---

## 🧪 Safe practice targets

Only scan systems you are authorized to test. These are **intentionally
vulnerable** targets that explicitly permit scanning:

- `http://testphp.vulnweb.com` — Acunetix test site (nginx / PHP)
- `http://testasp.vulnweb.com` — Acunetix test site (IIS / ASP.NET)
- `scanme.nmap.org` — Nmap's own authorized scan target
- **DVWA** or **OWASP Juice Shop** — run locally and scan `localhost`

> Tip: for the HTTP-based modules, type the full `http://` URL so the request
> isn't blocked by an HTTPS redirect.

---

## ⚠️ Known limitations

- **SQLi** is error-based only; it won't catch blind/time-based injection.
- **XSS** checks reflected payloads in forms only, with no DOM/context awareness.
- **Directory busting** uses a small built-in wordlist.
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
