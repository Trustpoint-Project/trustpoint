"""Forms for the TrustPoint setup wizard."""
from __future__ import annotations

import ipaddress
from typing import Any

from django import forms
from django.utils.translation import gettext_lazy as _


class EmptyForm(forms.Form):
    """A form without any fields."""


class StartupWizardTlsCertificateForm(forms.Form):
    """Form for collecting TLS server certificate details."""
    ipv4_addresses = forms.CharField(
        label=_('IPv4-Addresses (comma-separated list)'), initial='127.0.0.1, ', required=False
    )
    ipv6_addresses = forms.CharField(label=_('IPv6-Addresses (comma-separated list)'), initial='::1, ', required=False)
    domain_names = forms.CharField(
        label=_('Domain-Names (comma-separated list)'), initial='localhost, ', required=False
    )

    def clean_ipv4_addresses(self) -> list[ipaddress.IPv4Address]:
        """Validates and cleans IPv4 addresses input."""
        data = self.cleaned_data['ipv4_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv4Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError as e:
            msg = 'Contains an invalid IPv4-Address.'
            raise forms.ValidationError(msg) from e

    def clean_ipv6_addresses(self) -> list[ipaddress.IPv6Address]:
        """Validates and cleans IPv6 addresses input."""
        data = self.cleaned_data['ipv6_addresses'].strip()
        if not data:
            return []

        addresses = data.split(',')
        try:
            return [ipaddress.IPv6Address(address.strip()) for address in addresses if address.strip() != '']
        except ipaddress.AddressValueError as e:
            msg = 'Contains an invalid IPv6-Address.'
            raise forms.ValidationError(msg) from e

    def clean_domain_names(self) -> list[str]:
        """Validates and cleans domain names input."""
        data = self.cleaned_data['domain_names'].strip()
        if not data:
            return []

        domain_names = data.split(',')
        # TODO(AlexHx8472): Check for valid domains.  # noqa: FIX002
        return [domain_name.strip() for domain_name in domain_names if domain_name.strip() != '']

    def clean(self) -> dict[str, Any]:
        """Performs final validation to ensure at least one SAN entry is provided."""
        cleaned_data = super().clean() or {}
        ipv4_addresses = cleaned_data.get('ipv4_addresses')
        ipv6_addresses = cleaned_data.get('ipv6_addresses')
        domain_names = cleaned_data.get('domain_names')
        if not (ipv4_addresses or ipv6_addresses or domain_names):
            msg = 'At least one SAN entry is required.'
            raise forms.ValidationError(msg)
        return cleaned_data
