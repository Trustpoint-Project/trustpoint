import socket
import ipaddress
import ssl
import concurrent.futures
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class OTScanner:
    def __init__(self, timeout: float = 1.0, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers
        # EXPANDED PORT LIST: Includes standard web and the manager's industrial ports
        self.target_ports = [
            80, 443,            # HTTP/HTTPS
            4840,               # OPC UA
            1883, 8883,         # MQTT / Secure MQTT
            502, 102, 44818     # Other Industrial (Modbus/S7/ENIP)
        ]
        # We perform certificate analysis on these ports
        self.ssl_ports = [443, 8883]

    def _get_ips_from_cidr(self, cidr: str) -> List[str]:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Improved resolution similar to LanScan."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            try:
                # Fallback to Fully Qualified Domain Name
                name = socket.getfqdn(ip)
                return name if name != ip else None
            except:
                return None

    def _get_ssl_info(self, ip: str, port: int) -> Dict:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE 
        
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if not cert_bin:
                        return {"ssl_open": False}

                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    return {
                        "ssl_open": True,
                        "cert_object": cert, # This is the raw object for Step 3
                        "is_self_signed": (cert.issuer == cert.subject),
                        "issuer": cert.issuer.rfc4514_string(),
                        "subject": cert.subject.rfc4514_string(),
                        "valid_until": str(cert.not_valid_after_utc)
                    }
        except Exception:
            return {"ssl_open": False}

    def _scan_host(self, ip: str) -> Optional[Dict]:
        result = {"ip": ip, "hostname": None, "ports": [], "ssl_info": None}
        ports_found = False
        
        for port in self.target_ports:
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    result["ports"].append(port)
                    ports_found = True
                    if port in self.ssl_ports:
                        ssl_data = self._get_ssl_info(ip, port)
                        if ssl_data.get("ssl_open"):
                            result["ssl_info"] = ssl_data
            except:
                pass

        if not ports_found: return None
            
        result["hostname"] = self._resolve_hostname(ip)
        return result

    def scan_network(self, cidr: str) -> List[Dict]:
        ips = self._get_ips_from_cidr(cidr)
        discovered_devices = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self._scan_host, ip): ip for ip in ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                data = future.result()
                if data: discovered_devices.append(data)
        return discovered_devices