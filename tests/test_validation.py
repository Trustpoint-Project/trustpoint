"""Tests for validation utilities."""

import pytest

from trustpoint.util.validation import (
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
        ]
        for name in valid_names:
            validate_common_name_characters(name)

    def test_invalid_characters(self):
        """Test that common names with invalid characters fail."""
        invalid_names = [
            'device@example.com',
            'device.com/path',
            'device_with_underscore',
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

    def test_valid_webhook_urls(self):
        """Test that valid webhook URLs pass validation."""
        valid_urls = [
            'https://api.example.com/webhook',
            'http://webhook.example.org/notify',
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
            'http://192.168.1.1/webhook',  # Private IP (should fail if resolved)
        ]
        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_webhook_url(url)
