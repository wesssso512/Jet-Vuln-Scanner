<div align="center">

# 🛡️ Jet's Vulnerability Scanner

**A hybrid, multi-module desktop security tool for network and web vulnerability assessment.**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

> ⚠️ **Educational & Authorized Use Only** — This tool is intended for learning and testing systems you own or have explicit permission to scan.

</div>

---

## 📖 Overview

**Jet's Vulnerability Scanner** is a desktop security application developed as a graduation project at the **Syrian Virtual University (SVU)**. It provides a unified, dark-themed GUI to perform both network-level and web-level vulnerability scans without switching between multiple tools.

The tool combines **Socket-based TCP scanning**, **Nmap integration**, **web fingerprinting**, and **vulnerability detection** (SQLi, XSS, Directory Busting) — all driven by a multi-threaded engine and topped with a **Rule-Based AI Security Advisor** that generates human-readable security recommendations from scan results.

---

## ✨ Features

| Module | Description |
|---|---|
| 🔌 **Socket Scan** | Basic TCP Connect scan across common ports (21, 22, 80, 443, 3306, 8080) |
| 🗺️ **Nmap Advanced Scan** | Deep scan using Nmap subprocess with service version detection (`-sV`, `-F`, `-Pn`) |
| 🧬 **Tech Fingerprinting** | Detects Web Server, technology stack (X-Powered-By), and CMS (WordPress, Joomla, Drupal) |
| 💉 **SQL Injection Detection** | Tests URL parameters with error-based SQLi payloads across MySQL, MSSQL, Oracle, PostgreSQL |
| 🖥️ **XSS Detection** | Discovers forms and injects XSS payloads to detect reflected Cross-Site Scripting |
| 📂 **Directory Busting** | Brute-forces common hidden paths (admin, login, backup, config, robots.txt, etc.) |
| 🤖 **AI Security Advisor** | Rule-based engine that maps scan findings to security advice, risks, and remediation steps |
| 💾 **Report Export** | Saves full scan logs + AI advisor output to a timestamped `.txt` report |

---

## 🖼️ Screenshots

> *(Screenshots coming soon )*

---

## 🏗️ Project Structure

```
Vuln_Scanner/
│
├── main.py              # GUI layer — Tkinter Dark Mode UI, threading, AI advisor
├── port_scanner.py      # Network module — Socket scan + Nmap subprocess
├── web_scanner.py       # Web module — SQLi, XSS, Dir Busting, Fingerprinting
├── requirements.txt     # Python dependencies
└── README.md
```

---

## ⚙️ Tech Stack

- **Language:** Python 3.8+
- **GUI:** Tkinter (Dark Theme, Custom Styling)
- **Concurrency:** `threading` — Non-blocking scans
- **Network Layer:** `socket`, `subprocess` + Nmap
- **Web Layer:** `requests`, `BeautifulSoup4`
- **Logic:** Rule-Based Knowledge Base (AI Advisor)

---

## 🚀 Installation & Usage

### Prerequisites

- Python 3.8 or higher
- [Nmap](https://nmap.org/download.html) installed on your system *(required for Nmap Advanced Scan module only)*

### 1. Clone the repository

```bash
git clone https://github.com/wesssso512/Vuln_Scanner.git
cd Vuln_Scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python main.py
```

---

## 🧠 How It Works

```
User Input (Target IP / URL)
        │
        ▼
┌───────────────────┐
│  Input Validation  │  ← Regex: IP / Domain / localhost
└────────┬──────────┘
         │
         ▼
┌─────────────────────────────────────┐
│           Multi-Thread Engine        │
│                                     │
│  ┌──────────┐  ┌──────────────────┐ │
│  │  Network  │  │       Web        │ │
│  │  Module   │  │      Module      │ │
│  │           │  │                  │ │
│  │ • Socket  │  │ • Fingerprint    │ │
│  │ • Nmap    │  │ • SQLi / XSS     │ │
│  └──────────┘  │ • Dir Busting    │ │
│               └──────────────────┘ │
└────────────────────┬────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Rule-Based AI Advisor │  ← Maps findings → Advice
         └───────────┬───────────┘
                     │
                     ▼
              📄 Scan Report (.txt)
```

---

## ⚖️ Legal Disclaimer

This tool is developed **strictly for educational purposes** and authorized penetration testing. Unauthorized scanning of systems you do not own or have permission to test is **illegal** and **unethical**.

The developers assume **no liability** for any misuse of this software.

**Always test responsibly. Only scan systems you own or have explicit written permission to test.**

---

## 👨‍💻 Author

**Owais Boshnak**
- 🎓 Information Engineering — Syrian Virtual University (SVU)
- 🌐 [owais-boshnak.com](http://owais-boshnak.com)
- 💼 [GitHub](https://github.com/wesssso512)

---

## 🙏 Acknowledgments

- Supervised by **Dr. Al-Shayta** — SVU
- Inspired by real-world security tools: Nmap, Nikto, OWASP ZAP

---

<div align="center">

**⭐ If you found this useful, consider starring the repository!**

</div>
