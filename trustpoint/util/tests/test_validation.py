"""Tests for validation utilities."""

import ipaddress
import pytest
import socket
from unittest.mock import patch

from util.validation import (
    ValidationError,
    _is_ip_blocked,
    _validate_hostname_and_ip,
    _validate_port,
    _validate_webhook_scheme_and_host,
    validate_application_uri,
    validate_common_name_characters,
    validate_webhook_url,
)


class TestValidateCommonNameCharacters:
    """Test common name character validation."""

    def test_valid_common_names(self):
        """Test that valid common names pass validation."""
        valid_names = [
            'example-device',
            'Example Device',
            'device123',
            'device-123',
            'Device 123',
            'device_with_underscores',
            'device_123',
            'Device_Name_123',
        ]
        for name in valid_names:
            validate_common_name_characters(name)

    def test_invalid_characters(self):
        """Test that common names with invalid characters fail."""
        invalid_names = [
            'device@example.com',
            'device.com/path',
            'device@evil.com',
            'device#fragment',
        ]
        for name in invalid_names:
            with pytest.raises(ValidationError):
                validate_common_name_characters(name)


class TestValidateApplicationUri:
    """Test application URI validation."""

    def test_valid_application_uris(self):
        """Test that valid application URIs pass validation."""
        valid_uris = [
            'urn:example:device:123',
            'custom://device/123',
        ]
        for uri in valid_uris:
            validate_application_uri(uri)

    def test_invalid_application_uris(self):
        """Test that invalid application URIs fail."""
        invalid_uris = [
            'http://example.com',
            'https://example.com',
            'invalid-uri',
        ]
        for uri in invalid_uris:
            with pytest.raises(ValidationError):
                validate_application_uri(uri)


class TestValidateWebhookUrl:
    """Test webhook URL validation."""

class TestValidateWebhookUrl:
    """Test webhook URL validation."""

    @patch('socket.getaddrinfo')
    def test_valid_webhook_urls(self, mock_getaddrinfo):
        """Test that valid webhook URLs pass validation."""
        # Mock DNS resolution to return a public IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))
        ]
        valid_urls = [
            'https://api.example.com/webhook',
            'http://webhook.example.org/notify',
            'https://example.com:8443/webhook',
            'http://example.com:8080/notify',
            'https://example.com:10443/webhook',  # User port
            'https://192.168.1.1/webhook',  # Private IP (allowed)
            'http://10.0.0.1/notify',  # Private IP (allowed)
        ]
        for url in valid_urls:
            validate_webhook_url(url)

    def test_invalid_webhook_urls(self):
        """Test that invalid webhook URLs fail."""
        invalid_urls = [
            'ftp://example.com',  # Wrong scheme
            'not-a-url',  # Invalid URL
            'http://localhost/webhook',  # Localhost
            'https://127.0.0.1/notify',  # Loopback IP
            'http://example.com:22/webhook',  # Dangerous port (SSH)
            'https://example.com:3306/notify',  # Dangerous port (MySQL)
            'http://example.com:21/webhook',  # Invalid port
        ]
        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_webhook_url(url)

    def test_blocked_ip_ranges(self):
        """Test that various blocked IP ranges are rejected."""
        blocked_hosts = [
            '127.0.0.1',  # Loopback
            '0.0.0.0',    # This host
            '169.254.1.1',  # Link-local
            '192.0.2.1',   # Documentation
            '203.0.113.1', # Documentation
            '224.0.0.1',   # Multicast
            '240.0.0.1',   # Reserved
        ]
        for host in blocked_hosts:
            with pytest.raises(ValidationError):
                validate_webhook_url(f'https://{host}/webhook')

    def test_dns_resolution_failure(self):
        """Test that unresolvable hostnames are rejected."""
        with pytest.raises(ValidationError):
            validate_webhook_url('https://nonexistent-domain-12345.com/webhook')

    @patch('socket.getaddrinfo')
    def test_private_ip_allowed(self, mock_getaddrinfo):
        """Test that private IPs are allowed."""
        # Mock DNS resolution to return private IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))
        ]
        # Should not raise - private IPs are allowed
        validate_webhook_url('https://internal.example.com/webhook')


class TestIsIpBlocked:
    """Test IP blocking functionality."""

    def test_blocked_ips(self):
        """Test that blocked IP addresses are correctly identified."""
        blocked_ips = [
            '127.0.0.1',    # Loopback
            '0.0.0.0',      # This host
            '169.254.1.1',  # Link-local
            '192.0.2.1',    # Documentation
            '203.0.113.1',  # Documentation
            '224.0.0.1',    # Multicast
            '240.0.0.1',    # Reserved
            '100.64.0.1',   # Carrier-grade NAT
            '192.0.0.1',    # IETF protocol
            '198.18.0.1',   # Benchmarking
            '198.51.100.1', # Documentation
        ]
        for ip_str in blocked_ips:
            ip = ipaddress.ip_address(ip_str)
            assert _is_ip_blocked(ip), f'IP {ip_str} should be blocked'

    def test_allowed_ips(self):
        """Test that public and private IP addresses are not blocked."""
        allowed_ips = [
            '8.8.8.8',      # Google DNS
            '1.1.1.1',      # Cloudflare DNS
            '208.67.222.222',  # OpenDNS
            '192.168.1.1',  # Private IP (RFC 1918)
            '10.0.0.1',     # Private IP (RFC 1918)
            '172.16.0.1',   # Private IP (RFC 1918)
        ]
        for ip_str in allowed_ips:
            ip = ipaddress.ip_address(ip_str)
            assert not _is_ip_blocked(ip), f'IP {ip_str} should not be blocked'


class TestValidateWebhookSchemeAndHost:
    """Test URL scheme and host validation."""

    def test_valid_schemes_and_hosts(self):
        """Test that valid schemes and hosts pass validation."""
        from urllib.parse import urlparse
        valid_urls = [
            'https://example.com/webhook',
            'http://webhook.example.org/notify',
        ]
        for url in valid_urls:
            parsed = urlparse(url)
            _validate_webhook_scheme_and_host(parsed)

    def test_invalid_schemes(self):
        """Test that invalid schemes fail validation."""
        from urllib.parse import urlparse
        invalid_urls = [
            'ftp://example.com',
            'file:///etc/passwd',
            'mailto:test@example.com',
        ]
        for url in invalid_urls:
            parsed = urlparse(url)
            with pytest.raises(ValidationError):
                _validate_webhook_scheme_and_host(parsed)

    def test_missing_scheme_or_host(self):
        """Test that URLs without scheme or host fail validation."""
        from urllib.parse import urlparse
        invalid_urls = [
            'example.com/webhook',  # No scheme
            'https://',             # No host
        ]
        for url in invalid_urls:
            parsed = urlparse(url)
            with pytest.raises(ValidationError):
                _validate_webhook_scheme_and_host(parsed)


class TestValidateWebhookPort:
    """Test port validation."""

    def test_valid_ports(self):
        """Test that valid ports pass validation."""
        from urllib.parse import urlparse
        valid_urls = [
            'https://example.com/webhook',        # No port (defaults to 443)
            'http://example.com/notify',          # No port (defaults to 80)
            'https://example.com:443/webhook',    # Standard HTTPS
            'http://example.com:80/notify',       # Standard HTTP
            'https://example.com:8443/webhook',   # Standard HTTPS alt
            'http://example.com:8080/notify',     # Standard HTTP alt
            'https://example.com:10443/webhook',  # User port
        ]
        for url in valid_urls:
            parsed = urlparse(url)
            _validate_port(parsed)

    def test_dangerous_ports(self):
        """Test that dangerous ports are blocked."""
        from urllib.parse import urlparse
        dangerous_ports = [22, 23, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 27017]
        for port in dangerous_ports:
            url = f'https://example.com:{port}/webhook'
            parsed = urlparse(url)
            with pytest.raises(ValidationError):
                _validate_port(parsed)

    def test_invalid_ports(self):
        """Test that invalid port numbers fail validation."""
        from urllib.parse import urlparse
        invalid_urls = [
            'https://example.com:21/webhook',     # Below minimum
            'https://example.com:1023/webhook',   # Below user port minimum
        ]
        for url in invalid_urls:
            parsed = urlparse(url)
            with pytest.raises(ValidationError):
                _validate_port(parsed)


class TestValidateWebhookHostnameAndIp:
    """Test hostname and IP validation."""

    def test_blocked_hostnames(self):
        """Test that blocked hostnames are rejected."""
        blocked_hosts = [
            'localhost',
            '127.0.0.1',
            '::1',
            '0.0.0.0',
            '0:0:0:0:0:0:0:0',
        ]
        for host in blocked_hosts:
            with pytest.raises(ValidationError):
                _validate_hostname_and_ip(host)

    @patch('socket.getaddrinfo')
    def test_blocked_ip_resolution(self, mock_getaddrinfo):
        """Test that hostnames resolving to blocked IPs are rejected."""
        blocked_ips = [
            ('127.0.0.1', 'Loopback'),
            ('169.254.1.1', 'Link-local'),
        ]
        for ip_str, desc in blocked_ips:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip_str, 443))
            ]
            with pytest.raises(ValidationError):
                _validate_hostname_and_ip('example.com')

    @patch('socket.getaddrinfo')
    def test_dns_resolution_error(self, mock_getaddrinfo):
        """Test that DNS resolution failures are handled."""
        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failure")
        with pytest.raises(ValidationError):
            _validate_hostname_and_ip('nonexistent.example.com')

    @patch('socket.getaddrinfo')
    def test_valid_hostname(self, mock_getaddrinfo):
        """Test that valid hostnames resolving to public IPs pass."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))
        ]
        # Should not raise
        _validate_hostname_and_ip('example.com')
