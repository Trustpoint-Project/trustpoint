"""Devices filters.

Defines the `DeviceFilter` used to filter the devices list view.
"""

import django_filters
from django import forms
from django.utils.translation import gettext_lazy as _

from devices.models import DeviceModel
from pki.models import DomainModel


class DeviceFilter(django_filters.FilterSet):
    """FilterSet for the devices list page.

    Exposes three fields:
      * common_name: case-insensitive substring match
      * serial_number: case-insensitive substring match
      * domain: exact match via dropdown
    """

    common_name = django_filters.CharFilter(
        label='Device',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('Search…')}),
    )
    domain = django_filters.ModelChoiceFilter(
        queryset=DomainModel.objects.all(),
        label='Domain',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )
    serial_number = django_filters.CharFilter(
        label='Serial',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('Serial…')}),
    )

    class Meta:
        """Meta class configuration."""

        model = DeviceModel
        fields = ('common_name', 'domain', 'serial_number')
