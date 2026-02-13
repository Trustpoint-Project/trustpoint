"""Scanner logic for industrial and standard network protocols."""

import concurrent.futures
import ipaddress
import socket
import ssl
from threading import Event
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class OTScanner:
    """Detects open ports and SSL certificates on network hosts."""

    def __init__(self, target_ports: list[int], timeout: float = 0.8, max_workers: int = 40) -> None:
        """Initialize scanning parameters and shutdown event."""
        self.timeout = timeout
        self.max_workers = max_workers
        self.stop_requested = Event()
        self.target_ports = target_ports
        self.ssl_ports = [443, 8883]

    def _get_ips_from_range(self, start_ip: str, end_ip: str) -> list[str]:
        """Generate a list of IPv4 addresses from a start and end point."""
        try:
            start = int(ipaddress.IPv4Address(start_ip))
            end = int(ipaddress.IPv4Address(end_ip))
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
        except ValueError:
            return []

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve hostnames using system name resolution and FQDN fallbacks."""
        if self.stop_requested.is_set():
            return ''

        try:
            hostname, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        except (OSError, socket.herror, socket.gaierror):
            try:
                name = socket.getfqdn(ip)
            except (OSError, UnicodeError):
                return ''
            else:
                return name if name != ip else ''
        else:
            return hostname

    def _get_ssl_info(self, ip: str, port: int) -> dict[str, Any]:
        """Establish a connection and extract X509 certificate metadata."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection((ip, port), timeout=self.timeout) as sock,
                context.wrap_socket(sock, server_hostname=ip) as ssock,
            ):
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
        except (ssl.SSLError, OSError, ValueError):
            return {'ssl_open': False}

    def _scan_host(self, ip: str) -> dict[str, Any] | None:
        """Probe a single host for all target ports and security metadata."""
        if self.stop_requested.is_set():
            return None

        found_ports: list[int] = []
        result: dict[str, Any] = {'ip': ip, 'hostname': '', 'ports': found_ports, 'ssl_info': {}}
        found = False

        for port in self.target_ports:
            if self.stop_requested.is_set():
                return None
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

        if not found or self.stop_requested.is_set():
            return None

        result['hostname'] = self._resolve_hostname(ip)
        return result

    def scan_network(self, start_ip: str, end_ip: str) -> list[dict[str, Any]]:
        """Orchestrate concurrent host scanning with instant shutdown support."""
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
                except concurrent.futures.CancelledError:
                    continue
                except Exception:  # noqa: BLE001, S112
                    continue
        return results
