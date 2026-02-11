"""Network scanning logic for industrial and standard protocols."""

import concurrent.futures
import ipaddress
import socket
import ssl
from threading import Event
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class OTScanner:
    """Scanner for detecting network protocols."""

    def __init__(self, target_ports: list[int], timeout: float = 1.0, max_workers: int = 40) -> None:
        """Initialize the scanner."""
        self.timeout = timeout
        self.max_workers = max_workers
        self.stop_requested = Event()
        self.target_ports = target_ports
        self.ssl_ports = [443, 8883]

    def _get_ips_from_range(self, start_ip: str, end_ip: str) -> list[str]:
        """Generate a list of IP strings from a range."""
        try:
            start = int(ipaddress.IPv4Address(start_ip))
            end = int(ipaddress.IPv4Address(end_ip))
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
        except ValueError:
            return []

    def _resolve_hostname(self, ip: str) -> str | None:
        """Resolve hostname via DNS or FQDN."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:  # noqa: BLE001
            try:
                name = socket.getfqdn(ip)
            except Exception:  # noqa: BLE001
                return None
            else:
                return name if name != ip else None

    def _get_ssl_info(self, ip: str, port: int) -> dict[str, Any]:
        """Extract SSL certificate information."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock, \
                 context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    return {'ssl_open': False}

                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                return {
                    'ssl_open': True,
                    'cert_object': cert,
                    'is_self_signed': (cert.issuer == cert.subject),
                    'issuer': cert.issuer.rfc4514_string(),
                    'subject': cert.subject.rfc4514_string(),
                }
        except Exception:  # noqa: BLE001
            return {'ssl_open': False}

    def _scan_host(self, ip: str) -> dict[str, Any] | None:
        """Scan a single host for open ports."""
        if self.stop_requested.is_set():
            return None

        found_ports: list[int] = []
        result: dict[str, Any] = {'ip': ip, 'hostname': None, 'ports': found_ports, 'ssl_info': None}
        found = False

        for port in self.target_ports:
            if self.stop_requested.is_set():
                break
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    found_ports.append(port)
                    found = True
                    if port in self.ssl_ports:
                        ssl_data = self._get_ssl_info(ip, port)
                        if ssl_data.get('ssl_open'):
                            result['ssl_info'] = ssl_data
            except (OSError, TimeoutError):
                continue

        if not found:
            return None

        result['hostname'] = self._resolve_hostname(ip)
        return result

    def scan_network(self, start_ip: str, end_ip: str) -> list[dict[str, Any]]:
        """Run multi-threaded network scan."""
        self.stop_requested.clear()
        ips = self._get_ips_from_range(start_ip, end_ip)
        results: list[dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self._scan_host, ip): ip for ip in ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                if self.stop_requested.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    data = future.result()
                    if data:
                        results.append(data)
                except Exception:  # noqa: S112, BLE001
                    continue
        return results
