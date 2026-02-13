import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import datetime
import threading
import port_scanner
import web_scanner
from urllib.parse import urlparse
import re
import os
import subprocess 

# --- UI Configuration (Dark Theme) ---
BG_COLOR = "#1e1e1e"
FRAME_BG = "#252526"
FG_COLOR = "#dcdcdc"
ACCENT_COLOR = "#007acc"
DANGER_COLOR = "#e51400"
SUCCESS_COLOR = "#4bb543"
ADVICE_COLOR = "#d2691e"

# --- DEFINING ALL FONTS (Fixed Missing Definitions) ---
FONT_MAIN = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_CODE = ("Consolas", 10)
BTN_FONT = ("Segoe UI", 9)
BTN_WIDTH = 14  
# -----------------------------------------------------

# --- The Knowledge Base ---
KNOWLEDGE_BASE = {
    "XSS": ("⚠️ Cross-Site Scripting (XSS) Detected",
            "• Meaning: The application allows attackers to inject malicious scripts into web pages viewed by other users.\n"
            "• Risk: Attackers can hijack user sessions, deface websites, or redirect users to malicious sites.\n"
            "• Fix: Sanitize all user inputs and implement Content Security Policy (CSP)."),
    
    "SQL Injection": ("⚠️ SQL Injection (SQLi) Detected",
            "• Meaning: The application accepts malicious SQL statements that can manipulate the database.\n"
            "• Risk: Attackers can access sensitive data, modify database records, or delete entire tables.\n"
            "• Fix: Use Prepared Statements (Parameterized Queries) and avoid dynamic SQL generation."),
    
    "Port 80": ("ℹ️ Port 80 (HTTP) is Open",
            "• Meaning: Standard web traffic port is unencrypted.\n"
            "• Risk: Data transmitted can be intercepted (Sniffing).\n"
            "• Fix: Enforce HTTPS (Port 443) and implement HSTS to encrypt all traffic."),
    
    "Port 21": ("⚠️ Port 21 (FTP) is Open",
            "• Meaning: File Transfer Protocol is active.\n"
            "• Risk: FTP sends passwords in clear text. Attackers can easily steal credentials.\n"
            "• Fix: Disable FTP and use SFTP (SSH File Transfer Protocol) instead."),
           
    "WordPress": ("ℹ️ WordPress CMS Detected",
            "• Meaning: The target is running on WordPress content management system.\n"
            "• Risk: Outdated plugins or themes are common attack vectors.\n"
            "• Fix: Keep WordPress core, themes, and plugins updated. Hide login pages."),
    
    "Apache": ("ℹ️ Apache Web Server Detected",
            "• Advice: Hide version info in config (ServerTokens Prod)."),
    
    "Port 22": ("ℹ️ Port 22 (SSH) is Open",
            "• Advice: Ensure root login is disabled and use key-based authentication.")
}

# --- VALIDATION ---
def is_valid_target(target_input):
    clean_target = target_input.replace("http://", "").replace("https://", "").replace("/", "").split(":")[0]
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_regex = r"^(?=.{1,255}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,6}$"
    if clean_target == "localhost": return True
    if re.match(ip_regex, clean_target) or re.match(domain_regex, clean_target): return True
    return False

def run_scan_thread():
    if not any([var_socket.get(), var_nmap.get(), var_tech.get(), var_sqli.get(), var_xss.get(), var_dir.get()]):
        messagebox.showwarning("Selection Error", "Please select at least one scanning module!", parent=root)
        return

    target_val = entry_target.get().strip()
    if not target_val:
        messagebox.showwarning("Input Error", "Target field cannot be empty.", parent=root)
        return
    
    if not is_valid_target(target_val):
        messagebox.showerror("Invalid Format", "The Target URL/IP seems invalid.\nCorrect formats:\n• google.com\n• 192.168.1.5", parent=root)
        return

    btn_save.config(state=tk.DISABLED)
    btn_advice.pack_forget()
    scan_thread = threading.Thread(target=perform_scan_logic)
    scan_thread.start()

def perform_scan_logic():
    target = entry_target.get().strip()
    btn_scan.config(state=tk.DISABLED, text="Scanning...", bg="#3e3e42")
    progress_bar.start(10)
    text_area.config(state=tk.NORMAL)
    text_area.delete(1.0, tk.END) 
    
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
        scanner_net = port_scanner.PortScanner() if (var_socket.get() or var_nmap.get()) else None
        scanner_web = web_scanner.WebScanner() if (var_tech.get() or var_sqli.get() or var_xss.get() or var_dir.get()) else None

        if var_socket.get():
            log_msg(f"\n[+] Module: Basic Socket Scan...", "section")
            socket_result = scanner_net.scan_ports_socket(target_ip)
            log_msg(socket_result, "success" if "OPEN" in socket_result else "normal")
        
        if var_nmap.get():
            log_msg(f"\n[+] Module: Nmap Advanced Scan...", "section")
            nmap_result = scanner_net.scan_ports_nmap(target_ip)
            log_msg(nmap_result, "normal")

        if var_tech.get():
            log_msg(f"\n[+] Module: Technology Fingerprinting...", "section")
            fingerprint_result = scanner_web.detect_cms_and_server(target_url)
            log_msg(fingerprint_result, "info")
        
        if var_sqli.get():
            log_msg(f"\n[+] Module: SQL Injection Scan...", "section")
            sqli_result = scanner_web.check_sql_injection(target_url)
            if "[!!!]" in sqli_result: log_msg(sqli_result, "danger")
            else: log_msg(sqli_result, "safe")

        if var_xss.get():
            log_msg(f"\n[+] Module: XSS Vulnerability Scan...", "section")
            xss_result = scanner_web.scan_xss(target_url)
            if "[!!!]" in xss_result: log_msg(xss_result, "danger")
            else: log_msg(xss_result, "safe")
            
        if var_dir.get():
            log_msg(f"\n[+] Module: Directory Busting...", "section")
            parsed_uri = urlparse(target_url)
            base_url = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
            dir_result = scanner_web.scan_directories(base_url)
            log_msg(dir_result, "info")

    except Exception as e:
        log_msg(f"\n[!] Critical Error: {str(e)}", "danger")

    log_msg(f"\n[✓] Selected Scans Completed.", "success")
    btn_scan.config(state=tk.NORMAL, text="Start Scan", bg=ACCENT_COLOR)
    btn_save.config(state=tk.NORMAL) 
    progress_bar.stop()
    text_area.config(state=tk.DISABLED)
    btn_advice.pack(pady=5)

def log_msg(message, tag="normal"):
    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END, message + "\n", tag)
    text_area.see(tk.END)
    text_area.config(state=tk.DISABLED)

def get_advice_content():
    logs = text_area.get(1.0, tk.END)
    advice_found = []
    if "XSS" in logs and "[!!!]" in logs: advice_found.append(KNOWLEDGE_BASE["XSS"])
    if "SQL Injection" in logs and "[!!!]" in logs: advice_found.append(KNOWLEDGE_BASE["SQL Injection"])
    if "Port 80" in logs and "open" in logs: advice_found.append(KNOWLEDGE_BASE["Port 80"])
    if "Port 21" in logs and "open" in logs: advice_found.append(KNOWLEDGE_BASE["Port 21"])
    if "Port 22" in logs and "open" in logs: advice_found.append(KNOWLEDGE_BASE["Port 22"])
    if "WordPress" in logs: advice_found.append(KNOWLEDGE_BASE["WordPress"])
    if "Apache" in logs: advice_found.append(KNOWLEDGE_BASE["Apache"])
    return advice_found

# --- Styling Constants for Dialogs ---
DIALOG_BTN_FONT = ("Segoe UI", 9)
DIALOG_BTN_WIDTH = 15 
# --- Custom Dark Dialog 1 (The Question) ---
def custom_ask_report():
    dialog = tk.Toplevel(root)
    dialog.title("Report Options")
    dialog.geometry("450x180")
    dialog.configure(bg="#2d2d30")
    dialog.resizable(False, False)
    
    # Center the window
    x = root.winfo_x() + (root.winfo_width() // 2) - 225
    y = root.winfo_y() + (root.winfo_height() // 2) - 90
    dialog.geometry(f"+{x}+{y}")
    
    dialog.transient(root)
    dialog.grab_set()
    
    # Icon
    lbl_icon = tk.Label(dialog, text="❓", font=("Segoe UI", 30), bg="#2d2d30", fg="#0099ff")
    lbl_icon.place(x=25, y=30)
    
    # Text
    lbl_msg = tk.Label(dialog, text="Include AI Security Advice in the report?", 
                       bg="#2d2d30", fg="white", font=("Segoe UI", 11))
    lbl_msg.place(x=90, y=45)

    user_choice = {"value": None}

    def on_yes():
        user_choice["value"] = True
        dialog.destroy()

    def on_no():
        user_choice["value"] = False
        dialog.destroy()

    def on_cancel():
        user_choice["value"] = None
        dialog.destroy()

    # Buttons Frame (Centered)
    btn_frame = tk.Frame(dialog, bg="#2d2d30")
    btn_frame.pack(side=tk.BOTTOM, pady=25)

    # All buttons have same Width & Font
    btn_yes = tk.Button(btn_frame, text="Yes", bg=SUCCESS_COLOR, fg="white", font=DIALOG_BTN_FONT, width=DIALOG_BTN_WIDTH, command=on_yes)
    btn_yes.pack(side=tk.LEFT, padx=10)

    btn_no = tk.Button(btn_frame, text="No", bg=ACCENT_COLOR, fg="white", font=DIALOG_BTN_FONT, width=DIALOG_BTN_WIDTH, command=on_no)
    btn_no.pack(side=tk.LEFT, padx=10)

    btn_cancel = tk.Button(btn_frame, text="Cancel", bg="#444444", fg="white", font=DIALOG_BTN_FONT, width=DIALOG_BTN_WIDTH, command=on_cancel)
    btn_cancel.pack(side=tk.LEFT, padx=10)

    root.wait_window(dialog)
    return user_choice["value"]

# --- Custom Dark Dialog 2 (The Result) ---
def show_post_save_options(file_path):
    popup = tk.Toplevel(root)
    popup.title("Report Saved")
    popup.geometry("450x200")
    popup.configure(bg="#2d2d30")
    popup.resizable(False, False)
    
    # Center the window
    x = root.winfo_x() + (root.winfo_width() // 2) - 225
    y = root.winfo_y() + (root.winfo_height() // 2) - 100
    popup.geometry(f"+{x}+{y}")
    
    popup.transient(root)
    popup.grab_set()
    
    # Icon
    lbl_icon = tk.Label(popup, text="✅", font=("Segoe UI", 30), bg="#2d2d30", fg=SUCCESS_COLOR)
    lbl_icon.pack(pady=(15, 0))
    
    # Text
    lbl_msg = tk.Label(popup, text="Report saved successfully!", bg="#2d2d30", fg="white", font=("Segoe UI", 12, "bold"))
    lbl_msg.pack()
    
    # Filename (Truncate if too long)
    display_name = os.path.basename(file_path)
    if len(display_name) > 40: display_name = display_name[:37] + "..."
    lbl_path = tk.Label(popup, text=display_name, bg="#2d2d30", fg="#aaaaaa", font=("Consolas", 9))
    lbl_path.pack(pady=5)

    action_frame = tk.Frame(popup, bg="#2d2d30")
    action_frame.pack(side=tk.BOTTOM, pady=20)

    def open_file():
        try: os.startfile(file_path)
        except Exception as e: messagebox.showerror("Error", f"Cannot open file: {e}", parent=root)
        popup.destroy()

    def open_folder():
        try: subprocess.Popen(f'explorer /select,"{os.path.abspath(file_path)}"')
        except Exception as e: messagebox.showerror("Error", f"Cannot open folder: {e}", parent=root)
        popup.destroy()

    # Same Width as previous dialog (DIALOG_BTN_WIDTH)
    btn_file = tk.Button(action_frame, text="Open Report", bg="#2d8a55", fg="white", font=DIALOG_BTN_FONT, width=DIALOG_BTN_WIDTH, command=open_file)
    btn_file.pack(side=tk.LEFT, padx=10)

    btn_folder = tk.Button(action_frame, text="Open Location", bg=ACCENT_COLOR, fg="white", font=DIALOG_BTN_FONT, width=DIALOG_BTN_WIDTH, command=open_folder)
    btn_folder.pack(side=tk.LEFT, padx=10)

    btn_done = tk.Button(action_frame, text="Done", bg="#444444", fg="white", font=DIALOG_BTN_FONT, width=DIALOG_BTN_WIDTH, command=popup.destroy)
    btn_done.pack(side=tk.LEFT, padx=10)


def save_report():
    content = text_area.get(1.0, tk.END)
    if len(content.strip()) < 10:
        messagebox.showwarning("Warning", "No results to save!", parent=root)
        return
    
    choice = custom_ask_report()
    if choice is None: return

    if choice:
        advice_list = get_advice_content()
        if advice_list:
            content += "\n" + "="*60 + "\n AI SECURITY ADVISOR REPORT \n" + "="*60 + "\n\n"
            for title, body in advice_list:
                content += f"{title}\n{body}\n\n{'-'*40}\n\n"
        else:
            content += "\n\n[!] No specific security advice generated."

    file_name = f"Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(content)
        show_post_save_options(file_name)
    except Exception as e:
        messagebox.showerror("Error", f"Could not save report: {e}", parent=root)

def show_advice_window():
    advice_list = get_advice_content()
    advice_window = tk.Toplevel(root)
    advice_window.title("AI Security Advisor")
    advice_window.geometry("700x550")
    advice_window.configure(bg="#2d2d30")
    
    lbl_head = tk.Label(advice_window, text="Security Recommendations", bg="#2d2d30", fg="#ffcc00", font=("Segoe UI", 16, "bold"))
    lbl_head.pack(pady=15)
    
    txt_advice = scrolledtext.ScrolledText(advice_window, width=80, height=25, font=("Segoe UI", 11), bg="#1e1e1e", fg="#dcdcdc", relief="flat", padx=15, pady=15)
    txt_advice.pack(padx=20, pady=10, fill="both", expand=True)
    
    txt_advice.tag_config("header", foreground=ADVICE_COLOR, font=("Segoe UI", 12, "bold"))
    txt_advice.tag_config("body", foreground="#ffffff")
    
    if not advice_list:
        txt_advice.insert(tk.END, "✅ Good Status!\n\nNo critical issues requiring advice were detected.", "body")
    else:
        for title, body in advice_list:
            txt_advice.insert(tk.END, f"{title}\n", "header")
            txt_advice.insert(tk.END, f"{body}\n\n", "body")
            txt_advice.insert(tk.END, "-"*50 + "\n\n", "safe")

    txt_advice.config(state=tk.DISABLED)
    btn_close = tk.Button(advice_window, text="Close", bg="#444444", fg="white", font=("Segoe UI", 10), command=advice_window.destroy, width=10)
    btn_close.pack(pady=10)

def clear_logs():
    text_area.config(state=tk.NORMAL)
    text_area.delete(1.0, tk.END)
    text_area.config(state=tk.DISABLED)
    btn_advice.pack_forget()
    btn_save.config(state=tk.DISABLED)

def show_about():
    messagebox.showinfo("About", "SVU Vulnerability Scanner v2.0\nDeveloped by SVU Students\nSupervised by Dr. Al-Shayta", parent=root)

# --- GUI Setup ---
root = tk.Tk()
root.title("SVU SecScanner | PR2 Project")
root.geometry("900x750")
root.configure(bg=BG_COLOR)

menubar = tk.Menu(root)
file_menu = tk.Menu(menubar, tearoff=0)
file_menu.add_command(label="Save Report", command=save_report)
file_menu.add_command(label="Clear Logs", command=clear_logs)
file_menu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=file_menu)
help_menu = tk.Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=show_about)
menubar.add_cascade(label="Help", menu=help_menu)
root.config(menu=menubar)

header_frame = tk.Frame(root, bg=FRAME_BG, pady=15)
header_frame.pack(fill="x")
lbl_title = tk.Label(header_frame, text="SVU Vulnerability Scanner", bg=FRAME_BG, fg="white", font=("Segoe UI", 20, "bold"))
lbl_title.pack()
lbl_subtitle = tk.Label(header_frame, text="Advanced Network & Web Security Tool", bg=FRAME_BG, fg="#aaaaaa", font=("Segoe UI", 11))
lbl_subtitle.pack()

input_frame = tk.Frame(root, bg=BG_COLOR, pady=15)
input_frame.pack()
lbl_target = tk.Label(input_frame, text="Target URL / IP:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_BOLD)
lbl_target.grid(row=0, column=0, padx=10)
entry_target = tk.Entry(input_frame, width=50, font=FONT_CODE, bg="#333333", fg="white", insertbackground="white", relief="flat")
entry_target.grid(row=0, column=1, padx=10, ipady=5)

options_frame = tk.LabelFrame(root, text=" Select Scanning Modules ", bg=BG_COLOR, fg="#ffffff", font=("Segoe UI", 10, "bold"), labelanchor="n")
options_frame.pack(pady=10, padx=30, fill="x")

var_socket = tk.BooleanVar(value=False)
var_nmap = tk.BooleanVar(value=False)
var_tech = tk.BooleanVar(value=False)
var_sqli = tk.BooleanVar(value=False)
var_xss = tk.BooleanVar(value=False)
var_dir = tk.BooleanVar(value=False)

cb_style = {"bg": BG_COLOR, "fg": "#cccccc", "selectcolor": "#444444", "activebackground": BG_COLOR, "activeforeground": ACCENT_COLOR, "font": ("Segoe UI", 10)}

tk.Checkbutton(options_frame, text="Socket Scan (Basic)", variable=var_socket, **cb_style).grid(row=0, column=0, padx=20, pady=10, sticky="w")
tk.Checkbutton(options_frame, text="Nmap Advanced Scan", variable=var_nmap, **cb_style).grid(row=0, column=1, padx=20, pady=10, sticky="w")
tk.Checkbutton(options_frame, text="Tech Fingerprint", variable=var_tech, **cb_style).grid(row=0, column=2, padx=20, pady=10, sticky="w")
tk.Checkbutton(options_frame, text="SQL Injection Scan", variable=var_sqli, **cb_style).grid(row=1, column=0, padx=20, pady=10, sticky="w")
tk.Checkbutton(options_frame, text="XSS Vulnerability Scan", variable=var_xss, **cb_style).grid(row=1, column=1, padx=20, pady=10, sticky="w")
tk.Checkbutton(options_frame, text="Directory Busting", variable=var_dir, **cb_style).grid(row=1, column=2, padx=20, pady=10, sticky="w")

options_frame.grid_columnconfigure(0, weight=1)
options_frame.grid_columnconfigure(1, weight=1)
options_frame.grid_columnconfigure(2, weight=1)

btn_frame = tk.Frame(root, bg=BG_COLOR, pady=10)
btn_frame.pack()
btn_scan = tk.Button(btn_frame, text="Start Scan", bg=ACCENT_COLOR, fg="white", font=FONT_BOLD, width=15, relief="flat", command=run_scan_thread)
btn_scan.pack(side=tk.LEFT, padx=10)
btn_save = tk.Button(btn_frame, text="Save Report", bg="#2d8a55", fg="white", font=FONT_BOLD, width=15, relief="flat", command=save_report, state=tk.DISABLED)
btn_save.pack(side=tk.LEFT, padx=10)
btn_exit = tk.Button(btn_frame, text="Exit", bg=DANGER_COLOR, fg="white", font=FONT_BOLD, width=10, relief="flat", command=root.quit)
btn_exit.pack(side=tk.LEFT, padx=10)

progress_bar = ttk.Progressbar(root, mode='indeterminate', length=700)
progress_bar.pack(pady=10)

log_frame = tk.Frame(root, bg=BG_COLOR, padx=20, pady=5)
log_frame.pack(fill="both", expand=True)
lbl_logs = tk.Label(log_frame, text="Operation Logs:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_BOLD)
lbl_logs.pack(anchor="w")
text_area = scrolledtext.ScrolledText(log_frame, width=80, height=15, font=FONT_CODE, bg="#0e0e0e", fg=FG_COLOR, insertbackground="white", relief="flat")
text_area.pack(fill="both", expand=True)

text_area.tag_config("info", foreground="#569cd6")
text_area.tag_config("success", foreground="#4bb543")
text_area.tag_config("danger", foreground="#ff5555")
text_area.tag_config("safe", foreground="#888888")
text_area.tag_config("section", foreground="gold", font=("Consolas", 11, "bold"))

advice_frame = tk.Frame(root, bg=BG_COLOR, pady=10)
advice_frame.pack()
btn_advice = tk.Button(advice_frame, text="Analyze & Advise (AI)", bg=ADVICE_COLOR, fg="white", font=FONT_BOLD, width=20, relief="flat", command=show_advice_window)

lbl_footer = tk.Label(root, text="Developed by SVU Students | PR2 Project 2025-2026", bg=BG_COLOR, fg="#555555", font=("Segoe UI", 8))
lbl_footer.pack(side="bottom", pady=5)

if __name__ == "__main__":
    root.mainloop()