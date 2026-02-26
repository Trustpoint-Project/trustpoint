"""TLS Settings Model."""
from __future__ import annotations

from django.db import models


class TlsSettings(models.Model):
    """TLS settings model."""

    ipv4_address = models.GenericIPAddressField(protocol='IPv4', null=True, blank=True)

    def __str__(self) -> str:
        """Return a string representation of the TLS settings."""
        return f"TLS Settings (IPv4: {self.ipv4_address or 'None'})"

    @classmethod
    def get_first_ipv4_address(cls) -> str:
        """Get the first IPv4 address or a default value."""
        try:
            network_settings = cls.objects.get(id=1)
            ipv4_address = network_settings.ipv4_address
            if ipv4_address is None:
                return '127.0.0.1'
        except cls.DoesNotExist:
            return '127.0.0.1'
        else:
            return ipv4_address
