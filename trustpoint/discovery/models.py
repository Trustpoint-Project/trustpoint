# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Models for the network discovery module."""

from django.db import models

from pki.models.certificate import CertificateModel


class DiscoveryScan(models.Model):
    """Shared state for the single queued or running network scan."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    scan_id = models.UUIDField(null=True, editable=False)
    is_running = models.BooleanField(default=False)
    stop_pending = models.BooleanField(default=False)
    start_ip = models.GenericIPAddressField(protocol='IPv4', default='10.100.13.1')
    end_ip = models.GenericIPAddressField(protocol='IPv4', default='10.100.13.254')
    started_at = models.DateTimeField(null=True)

    def __str__(self) -> str:
        """Identify the current discovery scan."""
        return f'Discovery scan {self.scan_id}'


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
