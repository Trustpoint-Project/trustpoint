"""Tests for the settings module."""

import pytest
from django.core.exceptions import ValidationError

from settings.models import TlsSettings


@pytest.mark.django_db
class TestTlsSettingsIpv4:
    """Test cases for the TlsSettings model's IPv4 address field."""

    def test_ipv4_address_valid(self) -> None:
        """Test creating a TlsSettings instance with a valid IPv4 address."""
        tls_setting = TlsSettings.objects.create(ipv4_address='192.168.1.1')
        assert tls_setting.ipv4_address == '192.168.1.1'

    def test_ipv4_address_null(self) -> None:
        """Test creating a TlsSettings instance with a null IPv4 address."""
        tls_setting = TlsSettings.objects.create(ipv4_address=None)
        assert tls_setting.ipv4_address is None

    def test_ipv4_address_blank(self) -> None:
        """Test creating a TlsSettings instance with a blank IPv4 address."""
        tls_setting = TlsSettings.objects.create()
        assert tls_setting.ipv4_address is None

    def test_invalid_ipv4_address(self) -> None:
        """Test creating a TlsSettings instance with an invalid IPv4 address."""
        tls_setting = TlsSettings(ipv4_address='invalid_ip')
        with pytest.raises(ValidationError):
            tls_setting.full_clean()

    def test_partial_update_of_ipv4_address(self) -> None:
        """Test updating the `ipv4_address` after creating the model."""
        tls_setting = TlsSettings.objects.create(ipv4_address='192.168.1.1')
        tls_setting.ipv4_address = '10.0.0.1'
        tls_setting.save()
        tls_setting.refresh_from_db()
        assert tls_setting.ipv4_address == '10.0.0.1'

    def test_ipv4_address_reject_ipv6(self) -> None:
        """Test the field rejects an IPv6 address."""
        tls_setting = TlsSettings(ipv4_address='invalid_ip')
        with pytest.raises(ValidationError):
            tls_setting.full_clean()

