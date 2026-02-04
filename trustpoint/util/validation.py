"""General validation utilities for Trustpoint."""

import ipaddress
import re
import socket
from urllib.parse import ParseResult, urlparse

MIN_USER_PORT = 1024
MAX_PORT = 65535
STANDARD_HTTP_PORTS = (80, 8080, 8888)
STANDARD_HTTPS_PORTS = (443, 8443)

DANGEROUS_PORTS = {
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    110,  # POP3
    143,  # IMAP
    993,  # IMAPS
    995,  # POP3S
    3306, # MySQL
    5432, # PostgreSQL
    6379, # Redis
    27017,# MongoDB
}


class ValidationError(Exception):
    """Raised when validation fails."""


def validate_common_name_characters(common_name: str) -> None:
    """Validate that the common name contains only safe characters and no URL-like constructs."""
    if not re.match(r'^[a-zA-Z0-9 _-]+$', common_name):
        msg = 'Common name can only contain letters, numbers, spaces, underscores, and hyphens.'
        raise ValidationError(msg)
    parsed = urlparse(common_name)
    if parsed.scheme or parsed.netloc:
        msg = 'Common name cannot contain URL-like constructs.'
        raise ValidationError(msg)

def validate_application_uri(application_uri: str) -> None:
    """Validate that the application URI has a valid scheme and is not HTTP/HTTPS."""
    parsed = urlparse(application_uri)
    if not parsed.scheme:
        msg = 'Application URI must have a valid scheme.'
        raise ValidationError(msg)

    if parsed.scheme in ('http', 'https'):
        msg = 'HTTP and HTTPS schemes are not allowed for Application URI.'
        raise ValidationError(msg)

    if parsed.scheme == 'urn' and not parsed.path:
        msg = 'URN must have content after the scheme.'
        raise ValidationError(msg)


def _is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is in a blocked range for SSRF prevention."""
    blocked_ranges = [
        ipaddress.ip_network('0.0.0.0/8'),       # This host
        ipaddress.ip_network('100.64.0.0/10'),   # RFC 6598 (carrier-grade NAT)
        ipaddress.ip_network('127.0.0.0/8'),     # Loopback
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('192.0.0.0/24'),    # RFC 6890 (IETF protocol assignments)
        ipaddress.ip_network('192.0.2.0/24'),    # RFC 5737 (documentation)
        ipaddress.ip_network('198.18.0.0/15'),   # RFC 2544 (benchmarking)
        ipaddress.ip_network('198.51.100.0/24'), # RFC 5737 (documentation)
        ipaddress.ip_network('203.0.113.0/24'),  # RFC 5737 (documentation)
        ipaddress.ip_network('224.0.0.0/4'),     # Multicast
        ipaddress.ip_network('240.0.0.0/4'),     # Reserved
    ]

    return any(ip in network for network in blocked_ranges)


def _validate_webhook_scheme_and_host(parsed: ParseResult) -> None:
    """Validate URL scheme and host."""
    if not parsed.scheme or not parsed.netloc:
        msg = 'Webhook URL must be a valid URL with scheme and host.'
        raise ValidationError(msg)

    if parsed.scheme not in ('http', 'https'):
        msg = 'Webhook URL must use HTTP or HTTPS scheme.'
        raise ValidationError(msg)


def _validate_webhook_port(parsed: ParseResult) -> None:
    """Validate URL port number for SSRF prevention."""
    if parsed.port is None:
        return

    if parsed.port in DANGEROUS_PORTS:
        msg = f'Webhook URL port {parsed.port} is not allowed.'
        raise ValidationError(msg)

    allowed_ports = STANDARD_HTTP_PORTS if parsed.scheme == 'http' else STANDARD_HTTPS_PORTS
    if parsed.port not in allowed_ports and not (MIN_USER_PORT <= parsed.port <= MAX_PORT):
        port_list = ', '.join(map(str, allowed_ports))
        msg = f'Port {parsed.port} is not allowed. Use {port_list}, or {MIN_USER_PORT}-{MAX_PORT}.'
        raise ValidationError(msg)


def _validate_webhook_hostname_and_ip(hostname: str) -> None:
    """Validate hostname and resolve to safe IP addresses."""
    # ruff: noqa: S104
    if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0', '0:0:0:0:0:0:0:0'):
        msg = 'Webhook URL cannot target localhost or loopback addresses.'
        raise ValidationError(msg)

    try:
        ip_addresses = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for addr_info in ip_addresses:
            ip_str = addr_info[4][0]
            ip = ipaddress.ip_address(ip_str)

            if _is_ip_blocked(ip):
                msg = f'Webhook URL cannot target blocked IP address: {ip_str}'
                raise ValidationError(msg)

    except socket.gaierror:
        msg = f'Webhook URL hostname could not be resolved: {hostname}'
        raise ValidationError(msg) from None
    except ValueError as exc:
        msg = f'Webhook URL contains invalid IP address: {exc}'
        raise ValidationError(msg) from exc


def validate_webhook_url(url: str) -> None:
    """Validate that the webhook URL is safe and doesn't allow SSRF attacks.

    Implements comprehensive SSRF protection following OWASP guidelines:
    - Input validation and sanitization
    - URL parsing and scheme validation
    - Port number restrictions
    - Hostname validation
    - DNS resolution and IP address validation
    - Blocking of private/internal networks
    """
    parsed = urlparse(url)

    _validate_webhook_scheme_and_host(parsed)
    _validate_webhook_port(parsed)

    hostname = parsed.hostname
    if not hostname:
        msg = 'Webhook URL must have a valid hostname.'
        raise ValidationError(msg)

    _validate_webhook_hostname_and_ip(hostname)
