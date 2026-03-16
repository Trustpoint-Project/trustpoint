"""Tests for device utility validation functions."""

import pytest
from django import forms

from devices.utils import validate_application_uri, validate_common_name_characters


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
            with pytest.raises(forms.ValidationError):
                validate_common_name_characters(name)

    def test_url_like_constructs(self):
        """Test that URL-like constructs are rejected."""
        url_like_names = [
            'http://example.com',
            'https://evil.com',
            'ftp://test.com',
            'device.com:8080',
        ]
        for name in url_like_names:
            with pytest.raises(forms.ValidationError):
                validate_common_name_characters(name)


class TestValidateApplicationUri:
    """Test application URI validation."""

    def test_valid_application_uris(self):
        """Test that valid application URIs pass validation."""
        valid_uris = [
            'urn:example:device:123',
            'custom://device/123',
            'opc.tcp://device.example.com:4840',
        ]
        for uri in valid_uris:
            validate_application_uri(uri)

    def test_invalid_application_uris(self):
        """Test that invalid application URIs fail."""
        invalid_uris = [
            'http://example.com',
            'https://example.com',
            'invalid-uri',
            '',  # Empty string
        ]
        for uri in invalid_uris:
            with pytest.raises(forms.ValidationError):
                validate_application_uri(uri)

    def test_http_https_rejected(self):
        """Test that HTTP and HTTPS schemes are rejected."""
        http_uris = [
            'http://example.com/app',
            'https://secure.example.com/api',
        ]
        for uri in http_uris:
            with pytest.raises(forms.ValidationError):
                validate_application_uri(uri)
