import socket
import ipaddress
import ssl
import sys
import concurrent.futures
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class OTScanner:
    def __init__(self, timeout: float = 1.0, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers
        # EXPANDED PORT LIST (Web + Industrial + Mgmt)
        self.target_ports = [
            80, 443,            # HTTP/HTTPS
            22,                 # SSH (Linux/Gateways)
            502,                # Modbus TCP (Common Industrial)
            102,                # Siemens S7 (PLCs)
            44818,              # EtherNet/IP (Rockwell PLCs)
            4840,               # OPC UA
            1883, 8883          # MQTT / MQTT Secure
        ]
        self.ssl_ports = [443, 8883]

    def _get_ips_from_cidr(self, cidr: str) -> List[str]:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
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
                        return {"ssl_open": True, "error": "No certificate provided"}

                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    is_self_signed = (cert.issuer == cert.subject)
                    
                    return {
                        "ssl_open": True,
                        "is_self_signed": is_self_signed,
                        "issuer": cert.issuer.rfc4514_string(),
                        "subject": cert.subject.rfc4514_string(),
                        "valid_until": str(cert.not_valid_after)
                    }
        except Exception as e:
            return {"ssl_open": False, "error": str(e)}

    def _scan_host(self, ip: str) -> Optional[Dict]:
        result = {
            "ip": ip,
            "hostname": None,
            "ports": [],
            "ssl_info": None
        }
        ports_open = False
        
        for port in self.target_ports:
            try:
                with socket.create_connection((ip, port), timeout=self.timeout) as s:
                    result["ports"].append(port)
                    ports_open = True
                    
                    if port in self.ssl_ports:
                        ssl_data = self._get_ssl_info(ip, port)
                        if ssl_data.get("ssl_open"):
                            result["ssl_info"] = ssl_data
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        if not ports_open:
            return None
            
        result["hostname"] = self._resolve_hostname(ip)
        return result

    def scan_network(self, cidr: str) -> List[Dict]:
        ips = self._get_ips_from_cidr(cidr)
        discovered_devices = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self._scan_host, ip): ip for ip in ips}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                data = future.result()
                if data:
                    discovered_devices.append(data)
        
        return discovered_devices
