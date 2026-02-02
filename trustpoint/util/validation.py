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

            # Block private IP ranges
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                msg = f'Webhook URL cannot target private IP address: {ip_str}'
                raise ValidationError(msg)

            # Block reserved ranges that could be used for SSRF
            if ip in ipaddress.ip_network('169.254.0.0/16'):  # Link-local
                msg = f'Webhook URL cannot target link-local IP address: {ip_str}'
                raise ValidationError(msg)

    except socket.gaierror:
        pass
    except ValueError:
        pass
