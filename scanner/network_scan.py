import nmap
from urllib.parse import urlparse
from config import PORT_SCAN_RANGE  # Importing port range from config

class NetworkScanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()

    def scan_ports(self):
        parsed_url = urlparse(self.target)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path  

        try:
            print(f"[+] Scanning {hostname} on ports {PORT_SCAN_RANGE}")  
            self.nm.scan(hostname, arguments=f"-p {PORT_SCAN_RANGE} -T4")

            if hostname not in self.nm.all_hosts():
                print(f"[!] No results for {hostname}. Target may be unreachable.")
                return []

            return [port for port in self.nm[hostname]['tcp'] if self.nm[hostname]['tcp'][port]['state'] == 'open']
        except Exception as e:
            print(f"[X] Error scanning {hostname}: {e}")
            return []
