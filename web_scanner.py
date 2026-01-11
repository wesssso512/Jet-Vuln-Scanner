import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class WebScanner:
    def __init__(self):
        self.sql_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        self.sql_errors = {
            "MySQL": ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark"],
            "SQL Server": ["unclosed quotation mark after the character string", "microsoft ole db provider for sql server"],
            "Oracle": ["quoted string not properly terminated", "oracle error"],
            "PostgreSQL": ["syntax error at or near", "unterminated quoted string"]
        }
        self.xss_payload = "<script>alert('XSS')</script>"
        
        self.common_dirs = [
            "admin", "login", "dashboard", "uploads", "images", "css", "js", 
            "backup", "db", "config", "portal", "test", "robots.txt"
        ]

    # --- NEW FEATURE: Fingerprinting ---
    def detect_cms_and_server(self, url):
        """
        Attempts to identify the technology stack (CMS, Server, etc.)
        using HTTP headers and page content.
        """
        results = []
        results.append(f"[*] Starting Technology Fingerprinting on: {url}...")
        
        try:
            # Send a standard GET request
            response = requests.get(url, timeout=5)
            headers = response.headers
            content = response.text.lower()
            
            # 1. Detect Web Server from Headers
            server = headers.get("Server", "Unknown")
            results.append(f"    [+] Web Server Detected: {server}")
            
            # 2. Detect Technology (X-Powered-By)
            powered_by = headers.get("X-Powered-By", None)
            if powered_by:
                results.append(f"    [+] Technology Stack: {powered_by}")
            
            # 3. Detect CMS based on specific keywords in HTML
            cms_detected = False
            if "wp-content" in content or "wordpress" in content:
                results.append(f"    [+] CMS Detected: WordPress")
                cms_detected = True
            
            if "joomla" in content:
                results.append(f"    [+] CMS Detected: Joomla")
                cms_detected = True
                
            if "drupal" in content:
                results.append(f"    [+] CMS Detected: Drupal")
                cms_detected = True
                
            if not cms_detected:
                results.append(f"    [?] CMS: Could not identify (Custom or Hidden)")
                
        except Exception as e:
            results.append(f"[-] Could not fingerprint: {str(e)}")
            
        return "\n".join(results)

    def check_sql_injection(self, url):
        """ Checks for SQL Injection """
        results = []
        results.append(f"[*] Starting SQL Injection Scan on: {url}...")
        
        if "?" not in url:
            results.append("[-] URL has no parameters to test for SQLi.")
            return "\n".join(results)

        is_vulnerable = False
        for payload in self.sql_payloads:
            target_url = f"{url}{payload}"
            try:
                response = requests.get(target_url, timeout=5)
                content = response.text.lower()
                for db_type, errors in self.sql_errors.items():
                    for error in errors:
                        if error in content:
                            results.append(f"[!!!] SQL Injection Vulnerability Found!")
                            results.append(f"    [+] Database: {db_type}")
                            results.append(f"    [+] Payload: {payload}")
                            is_vulnerable = True
                            break
                    if is_vulnerable: break
            except: pass
            if is_vulnerable: break

        if not is_vulnerable: results.append("[-] No simple SQL Injection errors found.")
        return "\n".join(results)

    def scan_xss(self, url):
        """ Checks for XSS """
        results = []
        results.append(f"[*] Starting XSS Scan on: {url}...")
        forms = self.get_all_forms(url)
        results.append(f"[*] Found {len(forms)} forms.")
        
        if not forms:
            results.append("[-] No forms found.")
            return "\n".join(results)

        is_vulnerable = False
        for form in forms:
            details = self.get_form_details(form)
            content = self.submit_form(details, url, self.xss_payload)
            if content and self.xss_payload in content:
                results.append(f"[!!!] XSS Vulnerability Found!")
                results.append(f"    [+] Form Action: {details['action']}")
                is_vulnerable = True
                
        if not is_vulnerable: results.append("[-] No XSS vulnerabilities found.")
        return "\n".join(results)

    def scan_directories(self, base_url):
        """ Scans for hidden directories """
        results = []
        results.append(f"[*] Starting Directory Busting on: {base_url}...")
        
        if not base_url.endswith("/"):
            base_url += "/"
            
        found_dirs = []
        
        for directory in self.common_dirs:
            target_url = urljoin(base_url, directory)
            try:
                res = requests.get(target_url, timeout=3)
                if res.status_code == 200:
                    results.append(f"[+] Found Directory: {target_url} (Status: 200 OK)")
                    found_dirs.append(target_url)
                elif res.status_code == 403:
                    results.append(f"[!] Found Directory (Forbidden): {target_url} (Status: 403)")
            except:
                pass
                
        if not found_dirs:
            results.append("[-] No common directories found.")
            
        return "\n".join(results)

    # --- Helpers ---
    def get_all_forms(self, url):
        try: return BeautifulSoup(requests.get(url).content, "html.parser").find_all("form")
        except: return []

    def get_form_details(self, form):
        details = {"action": form.attrs.get("action", "").lower(), "method": form.attrs.get("method", "get").lower(), "inputs": []}
        for input_tag in form.find_all("input"):
            details["inputs"].append({"type": input_tag.attrs.get("type", "text"), "name": input_tag.attrs.get("name")})
        return details

    def submit_form(self, form_details, url, value):
        target_url = urljoin(url, form_details["action"])
        data = {input_tag["name"]: value for input_tag in form_details["inputs"] if input_tag["type"] in ["text", "search"] and input_tag["name"]}
        if form_details["method"] == "post": return requests.post(target_url, data=data).text
        return requests.get(target_url, params=data).text