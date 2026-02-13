"""Models for the network discovery module."""

from django.db import models

from pki.models.certificate import CertificateModel


class DiscoveryPort(models.Model):
    """Stores ports to be included in network scans."""

    port_number = models.PositiveIntegerField(unique=True)
    description = models.CharField(max_length=255)

    def __str__(self) -> str:
        """Return string representation of the port."""
        return f'{self.port_number} ({self.description})'


class DiscoveredDevice(models.Model):
    """Inventory of discovered network assets."""

    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, default='')
    open_ports = models.JSONField(default=list, blank=True)
    ssl_info = models.JSONField(default=dict, blank=True, null=True)
    certificate_record = models.ForeignKey(
        CertificateModel,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='discovered_on_devices',
    )
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        """Return string representation of the device."""
        return f'{self.ip_address} ({self.hostname or "Unknown"})'
