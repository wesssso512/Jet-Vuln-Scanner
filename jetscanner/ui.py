"""Tkinter GUI — the only module that imports Tk.

Key fix vs V1: scanning runs on a worker thread, but **no widget is ever
touched from that thread**. All UI updates are marshalled back to the main
thread with ``root.after(...)``. Tkinter is not thread-safe; V1 crashed
intermittently because the worker wrote to widgets directly.

State lives on the ``JetScannerApp`` instance instead of module globals.
"""
from __future__ import annotations

import datetime
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable, Dict, List, Optional

from . import advisor, reporting
from .engine import MODULES, run_scan
from .models import ModuleResult, ScanReport, Severity
from .validators import InvalidTarget, normalize_target

# --- Theme -----------------------------------------------------------------
BG = "#1e1e1e"
FRAME_BG = "#252526"
FG = "#dcdcdc"
ACCENT = "#007acc"
DANGER = "#e51400"
SUCCESS = "#2d8a55"
FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_CODE = ("Consolas", 10)

# Log tag -> colour.
_TAGS = {
    "info": "#569cd6",
    "success": "#4bb543",
    "danger": "#ff5555",
    "muted": "#888888",
    "section": "gold",
    "normal": FG,
}

# Checkboxes mirror the engine's module registry: (key, label).
_MODULES = [(spec.key, spec.label) for spec in MODULES.values()]


class JetScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.vars: Dict[str, tk.BooleanVar] = {
            key: tk.BooleanVar(value=False) for key, _ in _MODULES
        }
        self.results: List[ModuleResult] = []
        self.started_at: Optional[datetime.datetime] = None
        self._scanning = False
        self._build_ui()

    # -- thread-safe UI marshalling --------------------------------------
    def _ui(self, func: Callable, *args) -> None:
        """Schedule ``func(*args)`` to run on the Tk main thread."""
        self.root.after(0, lambda: func(*args))

    # -- UI construction --------------------------------------------------
    def _build_ui(self) -> None:
        self.root.title("Jet Vulnerability Scanner V2")
        self.root.geometry("900x760")
        self.root.configure(bg=BG)

        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Report", command=self.save_report)
        file_menu.add_command(label="Clear Logs", command=self.clear_logs)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

        header = tk.Frame(self.root, bg=FRAME_BG, pady=15)
        header.pack(fill="x")
        tk.Label(header, text="Jet Vulnerability Scanner", bg=FRAME_BG,
                 fg="white", font=("Segoe UI", 20, "bold")).pack()
        tk.Label(header, text="Network & Web Security Tool — authorized use only",
                 bg=FRAME_BG, fg="#aaaaaa", font=("Segoe UI", 11)).pack()

        inp = tk.Frame(self.root, bg=BG, pady=15)
        inp.pack()
        tk.Label(inp, text="Target URL / IP:", bg=BG, fg=FG,
                 font=FONT_BOLD).grid(row=0, column=0, padx=10)
        self.entry = tk.Entry(inp, width=50, font=FONT_CODE, bg="#333333",
                              fg="white", insertbackground="white", relief="flat")
        self.entry.grid(row=0, column=1, padx=10, ipady=5)
        self.entry.bind("<Return>", lambda _e: self.start_scan())

        opts = tk.LabelFrame(self.root, text=" Scanning Modules ", bg=BG,
                             fg="white", font=FONT_BOLD, labelanchor="n")
        opts.pack(pady=10, padx=30, fill="x")
        cb_style = {"bg": BG, "fg": "#cccccc", "selectcolor": "#444444",
                    "activebackground": BG, "activeforeground": ACCENT, "font": FONT}
        for idx, (key, label) in enumerate(_MODULES):
            tk.Checkbutton(opts, text=label, variable=self.vars[key],
                           **cb_style).grid(row=idx // 3, column=idx % 3,
                                            padx=20, pady=10, sticky="w")
        for col in range(3):
            opts.grid_columnconfigure(col, weight=1)

        btns = tk.Frame(self.root, bg=BG, pady=10)
        btns.pack()
        self.btn_scan = tk.Button(btns, text="Start Scan", bg=ACCENT, fg="white",
                                  font=FONT_BOLD, width=15, relief="flat",
                                  command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=10)
        self.btn_save = tk.Button(btns, text="Save Report", bg=SUCCESS, fg="white",
                                  font=FONT_BOLD, width=15, relief="flat",
                                  command=self.save_report, state=tk.DISABLED)
        self.btn_save.pack(side=tk.LEFT, padx=10)
        self.btn_advice = tk.Button(btns, text="Show Advice", bg="#d2691e",
                                    fg="white", font=FONT_BOLD, width=15,
                                    relief="flat", command=self.show_advice,
                                    state=tk.DISABLED)
        self.btn_advice.pack(side=tk.LEFT, padx=10)
        tk.Button(btns, text="Exit", bg=DANGER, fg="white", font=FONT_BOLD,
                  width=10, relief="flat", command=self.root.quit).pack(
            side=tk.LEFT, padx=10)

        self.progress = ttk.Progressbar(self.root, mode="indeterminate", length=700)
        self.progress.pack(pady=10)

        log_frame = tk.Frame(self.root, bg=BG, padx=20, pady=5)
        log_frame.pack(fill="both", expand=True)
        tk.Label(log_frame, text="Operation Logs:", bg=BG, fg=FG,
                 font=FONT_BOLD).pack(anchor="w")
        self.log = scrolledtext.ScrolledText(log_frame, width=80, height=15,
                                             font=FONT_CODE, bg="#0e0e0e", fg=FG,
                                             insertbackground="white", relief="flat")
        self.log.pack(fill="both", expand=True)
        self.log.config(state=tk.DISABLED)
        for tag, colour in _TAGS.items():
            self.log.tag_config(tag, foreground=colour)
        self.log.tag_config("section", font=("Consolas", 11, "bold"),
                            foreground=_TAGS["section"])

        tk.Label(self.root, text="Jet Vulnerability Scanner V2",
                 bg=BG, fg="#555555", font=("Segoe UI", 8)).pack(
            side="bottom", pady=5)

    # -- logging ----------------------------------------------------------
    def _write(self, message: str, tag: str = "normal") -> None:
        self.log.config(state=tk.NORMAL)
        self.log.insert(tk.END, message + "\n", tag)
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    # -- scan orchestration ----------------------------------------------
    def start_scan(self) -> None:
        if self._scanning:
            return
        selected = [k for k, v in self.vars.items() if v.get()]
        if not selected:
            messagebox.showwarning("Selection Error",
                                   "Select at least one module.", parent=self.root)
            return
        target = self.entry.get()
        try:
            host, url = normalize_target(target)
        except InvalidTarget as exc:
            messagebox.showerror("Invalid Target", str(exc), parent=self.root)
            return

        self._scanning = True
        self.results = []
        self.btn_scan.config(state=tk.DISABLED, text="Scanning...")
        self.btn_save.config(state=tk.DISABLED)
        self.btn_advice.config(state=tk.DISABLED)
        self.progress.start(12)

        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.config(state=tk.DISABLED)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write(f"[*] Scan started {now}", "info")
        self._write(f"[*] Host: {host}   URL: {url}", "info")
        self._write("-" * 60)

        thread = threading.Thread(
            target=self._worker, args=(target, selected), daemon=True)
        thread.start()

    def _worker(self, target: str, selected: List[str]) -> None:
        """Runs off the main thread. Touches NO widgets directly."""
        report = run_scan(
            target,
            selected,
            on_module_start=lambda spec: self._ui(
                self._write, f"\n[+] Module: {spec.label} ...", "section"),
            on_result=lambda result: self._ui(self._render_result, result),
        )
        self._ui(self._finish, report)

    def _render_result(self, result: ModuleResult) -> None:
        if result.error and not result.findings:
            tag = "danger"
        elif any(f.severity.rank >= Severity.HIGH.rank for f in result.findings):
            tag = "danger"
        elif result.findings:
            tag = "success"
        else:
            tag = "muted"
        self._write(result.text, tag)

    def _finish(self, report: ScanReport) -> None:
        self.results = report.results
        self.started_at = report.started_at
        self.progress.stop()
        self.btn_scan.config(state=tk.NORMAL, text="Start Scan")
        self.btn_save.config(state=tk.NORMAL)
        if self._all_findings():
            self.btn_advice.config(state=tk.NORMAL)
        self._write("\n[\u2713] Scan complete.", "success")
        self._scanning = False

    # -- derived data -----------------------------------------------------
    def _all_findings(self):
        return [f for r in self.results for f in r.findings]

    # -- actions ----------------------------------------------------------
    def show_advice(self) -> None:
        advice = advisor.advise(self._all_findings())
        window = tk.Toplevel(self.root)
        window.title("Security Advisor")
        window.geometry("700x550")
        window.configure(bg="#2d2d30")
        tk.Label(window, text="Security Recommendations", bg="#2d2d30",
                 fg="#ffcc00", font=("Segoe UI", 16, "bold")).pack(pady=15)
        box = scrolledtext.ScrolledText(window, width=80, height=25,
                                        font=("Segoe UI", 11), bg="#1e1e1e",
                                        fg=FG, relief="flat", padx=15, pady=15)
        box.pack(padx=20, pady=10, fill="both", expand=True)
        box.tag_config("header", foreground="#d2691e",
                       font=("Segoe UI", 12, "bold"))
        if not advice:
            box.insert(tk.END, "No issues requiring advice were detected.")
        else:
            for title, body in advice:
                box.insert(tk.END, f"{title}\n", "header")
                box.insert(tk.END, f"{body}\n\n")
                box.insert(tk.END, "-" * 50 + "\n\n")
        box.config(state=tk.DISABLED)
        tk.Button(window, text="Close", bg="#444444", fg="white",
                  command=window.destroy, width=10).pack(pady=10)

    def save_report(self) -> None:
        if not self.results:
            messagebox.showwarning("Nothing to save",
                                   "Run a scan first.", parent=self.root)
            return
        include = messagebox.askyesnocancel(
            "Report Options",
            "Include the security advisor section in the report?",
            parent=self.root)
        if include is None:
            return
        advice = advisor.advise(self._all_findings()) if include else ()
        started = (self.started_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                   if self.started_at else "")
        content = reporting.build_report(
            target=self.entry.get().strip(),
            started_at=started,
            modules=self.results,
            advice=advice,
        )
        try:
            path = reporting.save_report(content)
        except OSError as exc:
            messagebox.showerror("Error", f"Could not save report: {exc}",
                                 parent=self.root)
            return

        if messagebox.askyesno("Report Saved",
                               f"Saved to:\n{path}\n\nOpen it now?",
                               parent=self.root):
            try:
                reporting.open_file(path)
            except OSError as exc:
                messagebox.showerror("Error", f"Cannot open file: {exc}",
                                     parent=self.root)

    def clear_logs(self) -> None:
        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.config(state=tk.DISABLED)
        self.results = []
        self.started_at = None
        self.btn_save.config(state=tk.DISABLED)
        self.btn_advice.config(state=tk.DISABLED)

    def _about(self) -> None:
        messagebox.showinfo(
            "About",
            "Jet Vulnerability Scanner V2\n"
            "Educational network & web scanner.\n"
            "Only scan systems you are authorized to test.",
            parent=self.root)


def launch() -> None:
    root = tk.Tk()
    JetScannerApp(root)
    root.mainloop()
