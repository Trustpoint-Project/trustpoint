# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for validation utilities."""

import socket
from unittest.mock import Mock, call

import pytest

from util.validation import (
    ValidationError,
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
            'device_with_underscore',
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

    @pytest.fixture(autouse=True)
    def dns_resolver(self, monkeypatch):
        """Keep DNS checks enabled while replacing the external resolver."""
        resolver = Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('93.184.216.34', 0)),
            ]
        )
        monkeypatch.setattr('util.validation.socket.getaddrinfo', resolver)
        return resolver

    def test_valid_webhook_urls(self, dns_resolver):
        """Test that valid webhook URLs pass validation."""
        valid_urls = [
            'https://api.example.com/webhook',
            'http://webhook.example.org/notify',
        ]
        for url in valid_urls:
            validate_webhook_url(url)

        assert dns_resolver.call_args_list == [
            call('api.example.com', None, socket.AF_UNSPEC, socket.SOCK_STREAM),
            call('webhook.example.org', None, socket.AF_UNSPEC, socket.SOCK_STREAM),
        ]

    def test_invalid_webhook_urls(self, dns_resolver):
        """Test that invalid webhook URLs fail."""
        invalid_urls = [
            'ftp://example.com',  # Wrong scheme
            'not-a-url',  # Invalid URL
            'http://localhost/webhook',  # Localhost
            'https://127.0.0.1/notify',  # Loopback IP
        ]
        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_webhook_url(url)

        dns_resolver.assert_not_called()

    @pytest.mark.parametrize('address', ['127.0.0.1', '169.254.169.254'])
    def test_hostname_resolving_to_blocked_address(self, dns_resolver, address):
        """A syntactically valid hostname must still pass resolved-address checks."""
        dns_resolver.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (address, 0)),
        ]
        with pytest.raises(ValidationError, match='blocked IP address'):
            validate_webhook_url('https://api.example.com/webhook')
        dns_resolver.assert_called_once()

    def test_unresolvable_hostname(self, dns_resolver):
        """Resolver failure is rejected without consulting external DNS."""
        dns_resolver.side_effect = socket.gaierror('Synthetic resolution failure')
        with pytest.raises(ValidationError, match='could not be resolved'):
            validate_webhook_url('https://api.example.com/webhook')
        dns_resolver.assert_called_once()
