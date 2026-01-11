import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import datetime
import threading
import port_scanner
import web_scanner
from urllib.parse import urlparse

# --- UI Configuration (Dark Theme) ---
BG_COLOR = "#1e1e1e"        # Main Background
FRAME_BG = "#252526"        # Panel Background
FG_COLOR = "#dcdcdc"        # Main Text Color
ACCENT_COLOR = "#007acc"    # Button Color (Blue)
DANGER_COLOR = "#e51400"    # Error/Exit Color (Red)
SUCCESS_COLOR = "#4bb543"   # Success Color (Green)
FONT_MAIN = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_CODE = ("Consolas", 10)

def run_scan_thread():
    """Starts the scanning process in a separate thread."""
    scan_thread = threading.Thread(target=perform_scan_logic)
    scan_thread.start()

def perform_scan_logic():
    """Main logic controller."""
    target = entry_target.get()
    
    if not target:
        messagebox.showwarning("Input Error", "Please enter a valid Target IP or URL.")
        return
    
    # UI Preparation
    btn_scan.config(state=tk.DISABLED, text="Scanning...", bg="#3e3e42")
    progress_bar.start(10)
    text_area.config(state=tk.NORMAL)
    text_area.delete(1.0, tk.END)
    
    # URL Parsing
    if not target.startswith("http"):
        target_ip = target
        target_url = f"http://{target}"
    else:
        target_url = target
        parsed = urlparse(target)
        target_ip = parsed.hostname if parsed.hostname else target

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg(f"[*] Scan started at: {current_time}", "info")
    log_msg(f"[*] Target IP: {target_ip}", "info")
    log_msg(f"[*] Target URL: {target_url}", "info")
    log_msg("-" * 60, "normal")

    try:
        # --- NETWORK SCAN ---
        scanner_net = port_scanner.PortScanner()
        
        log_msg(f"\n[+] Phase 1: Basic Socket Scan...", "section")
        socket_result = scanner_net.scan_ports_socket(target_ip)
        log_msg(socket_result, "success" if "OPEN" in socket_result else "normal")
        
        log_msg(f"\n[+] Phase 2: Nmap Advanced Scan...", "section")
        nmap_result = scanner_net.scan_ports_nmap(target_ip)
        log_msg(nmap_result, "normal")

        # --- WEB SCAN ---
        scanner_web = web_scanner.WebScanner()
        
        log_msg(f"\n[+] Phase 3: Technology Fingerprinting...", "section")
        fingerprint_result = scanner_web.detect_cms_and_server(target_url)
        log_msg(fingerprint_result, "info")
        
        log_msg(f"\n[+] Phase 4: SQL Injection Scan...", "section")
        sqli_result = scanner_web.check_sql_injection(target_url)
        if "[!!!]" in sqli_result:
            log_msg(sqli_result, "danger")
        else:
            log_msg(sqli_result, "safe")

        log_msg(f"\n[+] Phase 5: XSS Vulnerability Scan...", "section")
        xss_result = scanner_web.scan_xss(target_url)
        if "[!!!]" in xss_result:
            log_msg(xss_result, "danger")
        else:
            log_msg(xss_result, "safe")
            
        log_msg(f"\n[+] Phase 6: Directory Busting...", "section")
        parsed_uri = urlparse(target_url)
        base_url = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        dir_result = scanner_web.scan_directories(base_url)
        log_msg(dir_result, "info")

    except Exception as e:
        log_msg(f"\n[!] Critical Error: {str(e)}", "danger")

    log_msg(f"\n[✓] Full Scan Completed.", "success")
    btn_scan.config(state=tk.NORMAL, text="Start Scan", bg=ACCENT_COLOR)
    progress_bar.stop()
    text_area.config(state=tk.DISABLED)

def log_msg(message, tag="normal"):
    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END, message + "\n", tag)
    text_area.see(tk.END)
    text_area.config(state=tk.DISABLED)

def save_report():
    content = text_area.get(1.0, tk.END)
    if len(content.strip()) < 10:
        messagebox.showwarning("Warning", "No results to save!")
        return
    file_name = f"Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Success", f"Report saved: {file_name}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not save report: {e}")

def show_about():
    """Shows the About dialog with student names."""
    about_msg = (
        "SVU Vulnerability Scanner v1.0\n"
        "Project: PR2 (F24)\n\n"
        "Developed by:\n"
        "1. Owais Husam Al-Din Boshnaq\n"
        "2. Obada Ayman Asfour\n"
        "3. Mohammed Faisal Mousa\n\n"
        "Supervised by: Dr. Mohammed Al-Shayta"
    )
    messagebox.showinfo("About", about_msg)

def clear_logs():
    text_area.config(state=tk.NORMAL)
    text_area.delete(1.0, tk.END)
    text_area.config(state=tk.DISABLED)

# --- Main GUI Setup ---
root = tk.Tk()
root.title("SVU SecScanner | PR2 Project")
root.geometry("900x650")
root.configure(bg=BG_COLOR)

# --- NEW: Menu Bar ---
menubar = tk.Menu(root)

# File Menu
file_menu = tk.Menu(menubar, tearoff=0)
file_menu.add_command(label="Save Report", command=save_report)
file_menu.add_separator()
file_menu.add_command(label="Clear Logs", command=clear_logs)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=file_menu)

# Help Menu
help_menu = tk.Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)

root.config(menu=menubar)
# ---------------------

# 1. Header Frame
header_frame = tk.Frame(root, bg=FRAME_BG, pady=10)
header_frame.pack(fill="x")

lbl_title = tk.Label(header_frame, text="SVU Vulnerability Scanner", bg=FRAME_BG, fg="white", font=("Segoe UI", 18, "bold"))
lbl_title.pack()
lbl_subtitle = tk.Label(header_frame, text="Network & Web Security Tool", bg=FRAME_BG, fg="#aaaaaa", font=("Segoe UI", 10))
lbl_subtitle.pack()

# 2. Input Frame
input_frame = tk.Frame(root, bg=BG_COLOR, pady=20)
input_frame.pack()

lbl_target = tk.Label(input_frame, text="Target URL / IP:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_BOLD)
lbl_target.grid(row=0, column=0, padx=10)

entry_target = tk.Entry(input_frame, width=50, font=FONT_CODE, bg="#333333", fg="white", insertbackground="white", relief="flat")
entry_target.grid(row=0, column=1, padx=10, ipady=5)

# 3. Control Buttons
btn_frame = tk.Frame(root, bg=BG_COLOR, pady=10)
btn_frame.pack()

btn_scan = tk.Button(btn_frame, text="Start Scan", bg=ACCENT_COLOR, fg="white", font=FONT_BOLD, width=15, relief="flat", command=run_scan_thread)
btn_scan.pack(side=tk.LEFT, padx=10)

btn_save = tk.Button(btn_frame, text="Save Report", bg="#2d8a55", fg="white", font=FONT_BOLD, width=15, relief="flat", command=save_report)
btn_save.pack(side=tk.LEFT, padx=10)

btn_exit = tk.Button(btn_frame, text="Exit", bg=DANGER_COLOR, fg="white", font=FONT_BOLD, width=10, relief="flat", command=root.quit)
btn_exit.pack(side=tk.LEFT, padx=10)

# 4. Progress Indicator
progress_bar = ttk.Progressbar(root, mode='indeterminate', length=700)
progress_bar.pack(pady=10)

# 5. Logs / Output Area
log_frame = tk.Frame(root, bg=BG_COLOR, padx=20, pady=10)
log_frame.pack(fill="both", expand=True)

lbl_logs = tk.Label(log_frame, text="Operation Logs:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_BOLD)
lbl_logs.pack(anchor="w")

text_area = scrolledtext.ScrolledText(log_frame, width=80, height=20, font=FONT_CODE, bg="#0e0e0e", fg=FG_COLOR, insertbackground="white", relief="flat")
text_area.pack(fill="both", expand=True)

text_area.tag_config("info", foreground="#569cd6")
text_area.tag_config("success", foreground="#4bb543")
text_area.tag_config("danger", foreground="#ff5555")
text_area.tag_config("safe", foreground="#888888")
text_area.tag_config("section", foreground="gold", font=("Consolas", 11, "bold"))

# Footer
lbl_footer = tk.Label(root, text="Developed by SVU Students | PR2 Project 2025", bg=BG_COLOR, fg="#555555", font=("Segoe UI", 8))
lbl_footer.pack(side="bottom", pady=5)

if __name__ == "__main__":
    root.mainloop()