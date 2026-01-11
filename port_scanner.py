import socket
import subprocess
import os

class PortScanner:
    def __init__(self):
        """
        Initializes the scanner and locates the Nmap executable.
        We search common Windows installation paths to ensure stability.
        """
        # Default command if Nmap is in the system PATH
        self.nmap_executable = "nmap" 
        
        # List of common installation paths for Nmap on Windows
        possible_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]
        
        # Check if the executable exists in specific paths
        for path in possible_paths:
            if os.path.exists(path):
                # We wrap the path in quotes to handle spaces in directory names
                self.nmap_executable = f'"{path}"'
                break

    def scan_ports_socket(self, target_ip, ports=[21, 22, 80, 443, 3306, 8080]):
        """
        Performs a basic TCP Connect scan using Python's native Socket library.
        This demonstrates low-level networking concepts.
        """
        results = []
        results.append(f"[*] Starting Socket Scan on {target_ip}...")
        
        for port in ports:
            try:
                # Create a TCP socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)  # Set a short timeout to speed up scanning
                
                # Attempt to connect to the port
                result = s.connect_ex((target_ip, port))
                
                # If result is 0, the port is open
                if result == 0:
                    results.append(f"[+] Port {port} is OPEN")
                
                s.close()
            except Exception:
                pass
            
        results.append("[*] Socket Scan Completed.")
        return "\n".join(results)

    def scan_ports_nmap(self, target_ip):
        """
        Executes Nmap as a subprocess and captures the raw output.
        This method bypasses library compatibility issues by interacting directly with the OS.
        """
        scan_log = []
        scan_log.append(f"[*] Starting Nmap Scan on {target_ip}...")
        
        try:
            # Construct the Nmap command line arguments
            # -Pn: Treat host as online (skip ping)
            # -F: Fast scan (top 100 ports)
            # -sV: Probe open ports to determine service/version info
            command = f'{self.nmap_executable} -Pn -F -sV --version-intensity 0 -T4 {target_ip}'
            
            # Execute the command in the system shell
            process = subprocess.Popen(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            # Wait for the command to finish and capture output
            output, error = process.communicate()
            
            # Decode bytes to string (handling potential encoding errors)
            try:
                output_str = output.decode('utf-8', errors='ignore')
                error_str = error.decode('utf-8', errors='ignore')
            except:
                output_str = str(output)
                error_str = str(error)

            # Append the standard output (results) to logs
            if output_str:
                scan_log.append(output_str.strip())
            
            # Handle potential errors or warnings from stderr
            if error_str and not output_str:
                scan_log.append(f"[!] Nmap Output/Warning:\n{error_str}")
                
            # Fallback if absolutely nothing returned
            if not output_str and not error_str:
                 scan_log.append("[-] No output returned from Nmap command.")

        except Exception as e:
            scan_log.append(f"[!] Critical Error executing Nmap subprocess: {str(e)}")
            
        return "\n".join(scan_log)