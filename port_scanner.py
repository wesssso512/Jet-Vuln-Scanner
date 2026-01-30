import socket
import subprocess
import os

class PortScanner:
    def __init__(self):
        """
        Initializes the scanner and locates the Nmap executable.
        """
        self.nmap_executable = "nmap" 
        possible_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                self.nmap_executable = f'"{path}"'
                break

    def scan_ports_socket(self, target_ip, ports=[21, 22, 80, 443, 3306, 8080]):
        """
        Performs a basic TCP Connect scan.
        """
        results = []
        results.append(f"[*] Starting Socket Scan on {target_ip}...")
        
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    results.append(f"[+] Port {port} is OPEN")
                s.close()
            except Exception:
                pass
            
        results.append("[*] Socket Scan Completed.")
        return "\n".join(results)

    def scan_ports_nmap(self, target_ip):
        """
        Executes Nmap and cleans the output to show only relevant info.
        """
        scan_log = []
        scan_log.append(f"[*] Starting Nmap Scan on {target_ip}...")
        
        try:
            # Command: -Pn (No Ping), -F (Fast), -sV (Versions)
            command = f'{self.nmap_executable} -Pn -F -sV --version-intensity 0 -T4 {target_ip}'
            
            process = subprocess.Popen(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            output, error = process.communicate()
            
            try:
                output_str = output.decode('utf-8', errors='ignore')
                error_str = error.decode('utf-8', errors='ignore')
            except:
                output_str = str(output)
                error_str = str(error)

            if output_str:
                # --- CLEANING LOGIC
                lines = output_str.splitlines()
                relevant_lines = []
                
                for line in lines:
                    # Keep lines that contain port info, service info, or OS info
                    if "PORT" in line and "STATE" in line: # Header
                        relevant_lines.append("\n" + line) # Add newline before header
                    elif "/tcp" in line or "/udp" in line: # Port rows
                        relevant_lines.append(line)
                    elif "Service Info" in line: # OS/Service details
                        relevant_lines.append("\n" + line)
                    elif "Running:" in line or "OS details:" in line: # OS details
                        relevant_lines.append(line)
                
                if relevant_lines:
                    scan_log.append("\n".join(relevant_lines))
                else:
                    # If filter removed everything, show raw output (fallback)
                    scan_log.append(output_str.strip())
            
            if error_str and not output_str:
                scan_log.append(f"[!] Nmap Output/Warning:\n{error_str}")
                
            if not output_str and not error_str:
                 scan_log.append("[-] No output returned from Nmap command.")

        except Exception as e:
            scan_log.append(f"[!] Critical Error executing Nmap subprocess: {str(e)}")
            
        return "\n".join(scan_log)