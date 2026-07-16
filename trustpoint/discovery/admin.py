"""Admin configuration for the network discovery module."""

from django.contrib import admin

from .models import DiscoveryPort


@admin.register(DiscoveryPort)
class DiscoveryPortAdmin(admin.ModelAdmin[DiscoveryPort]):
    """Admin interface for managing scan ports."""

    list_display = ('port_number', 'description')
    ordering = ('port_number',)
