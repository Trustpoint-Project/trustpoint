"""General validation utilities for Trustpoint."""

import ipaddress
import re
import socket
from urllib.parse import urlparse


class ValidationError(Exception):
    """Raised when validation fails."""


def validate_common_name_characters(common_name: str) -> None:
    """Validate that the common name contains only safe characters and no URL-like constructs.

    Since common_name is used in workflow contexts that may be interpolated into URLs,
    we restrict to characters that are safe for URL interpolation.
    """
    if not re.match(r'^[a-zA-Z0-9 -]+$', common_name):
        msg = 'Common name can only contain letters, numbers, spaces, and hyphens.'
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


def _is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is in a blocked range for SSRF prevention."""
    blocked_ranges = [
        ipaddress.ip_network('0.0.0.0/8'),       # This host
        ipaddress.ip_network('10.0.0.0/8'),      # RFC 1918 (private)
        ipaddress.ip_network('100.64.0.0/10'),   # RFC 6598 (carrier-grade NAT)
        ipaddress.ip_network('127.0.0.0/8'),     # Loopback
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('172.16.0.0/12'),   # RFC 1918 (private)
        ipaddress.ip_network('192.0.0.0/24'),    # RFC 6890 (IETF protocol assignments)
        ipaddress.ip_network('192.0.2.0/24'),    # RFC 5737 (documentation)
        ipaddress.ip_network('192.168.0.0/16'),  # RFC 1918 (private)
        ipaddress.ip_network('198.18.0.0/15'),   # RFC 2544 (benchmarking)
        ipaddress.ip_network('198.51.100.0/24'), # RFC 5737 (documentation)
        ipaddress.ip_network('203.0.113.0/24'),  # RFC 5737 (documentation)
        ipaddress.ip_network('224.0.0.0/4'),     # Multicast
        ipaddress.ip_network('240.0.0.0/4'),     # Reserved
    ]

    return any(ip in network for network in blocked_ranges)


def validate_webhook_url(url: str) -> None:
    """Validate that the webhook URL is safe and doesn't allow SSRF attacks."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        msg = 'Webhook URL must be a valid URL with scheme and host.'
        raise ValidationError(msg)

    if parsed.scheme not in ('http', 'https'):
        msg = 'Webhook URL must use HTTP or HTTPS scheme.'
        raise ValidationError(msg)

    # Prevent SSRF by blocking localhost and private IP ranges
    hostname = parsed.hostname
    if not hostname:
        msg = 'Webhook URL must have a valid hostname.'
        raise ValidationError(msg)

    # Block localhost variations
    # ruff: noqa: S104 - We are explicitly blocking these dangerous addresses
    if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0', '0:0:0:0:0:0:0:0'):
        msg = 'Webhook URL cannot target localhost or loopback addresses.'
        raise ValidationError(msg)

    try:
        # Resolve hostname to IP addresses
        ip_addresses = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for addr_info in ip_addresses:
            ip_str = addr_info[4][0]
            ip = ipaddress.ip_address(ip_str)

            if _is_ip_blocked(ip):
                msg = f'Webhook URL cannot target blocked IP address: {ip_str}'
                raise ValidationError(msg)

    except socket.gaierror:
        # DNS resolution failure - could indicate DNS rebinding attempt
        msg = f'Webhook URL hostname could not be resolved: {hostname}'
        raise ValidationError(msg) from None
    except ValueError as exc:
        # IP parsing failure
        msg = f'Webhook URL contains invalid IP address: {exc}'
        raise ValidationError(msg) from exc
