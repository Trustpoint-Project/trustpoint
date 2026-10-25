# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Convert owner credential form and API data into certificate request values."""

from typing import Any

from django.utils.translation import gettext as _
from trustpoint_core.oid import NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo


def build_request_data(
    cert_content_data: dict[str, Any],
    *,
    stringify_san_items: bool = False,
    keep_empty_sans: bool = False,
) -> dict[str, Any]:
    """Convert flat serializer data into the nested structure expected by the profile verifier."""
    request_data: dict[str, Any] = {
        'subj': {},
        'ext': {'subject_alternative_name': {}},
        'validity': {},
    }
    for field in (
        'common_name',
        'organization_name',
        'organizational_unit_name',
        'country_name',
        'state_or_province_name',
        'locality_name',
        'email_address',
    ):
        value = cert_content_data.get(field)
        if value:
            request_data['subj'][field] = value
    for field in ('dns_names', 'ip_addresses', 'rfc822_names', 'uris'):
        value = cert_content_data.get(field)
        if value:
            if isinstance(value, list):
                items = [
                    str(v).strip() if stringify_san_items else v.strip()
                    for v in value if str(v).strip()
                ]
            else:
                items = [v.strip() for v in str(value).split(',') if v.strip()]
            if items or keep_empty_sans:
                request_data['ext']['subject_alternative_name'][field] = items
    for field in ('days', 'hours', 'minutes', 'seconds'):
        value = cert_content_data.get(field)
        if value is not None:
            request_data['validity'][field] = int(value)
    return request_data


def public_key_info_from_key_type(key_type: str) -> PublicKeyInfo:
    """Convert a key_type string (e.g. 'RSA-2048', 'ECC-SECP256R1') to a PublicKeyInfo."""
    if key_type.startswith('RSA-'):
        key_size = int(key_type.split('-')[1])
        return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA, key_size=key_size)
    curve_name = key_type.split('-', 1)[1]
    named_curve = NamedCurve[curve_name.upper()]
    return PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC, named_curve=named_curve)


def build_cert_content_summary(cert_data: dict[str, Any]) -> dict[str, Any]:
    """Return a human-readable summary dict suitable for template rendering."""
    summary: dict[str, Any] = {'subject': {}, 'san': {}, 'validity': ''}
    for key, label in (
        ('common_name', 'Common Name (CN)'),
        ('organization_name', 'Organization (O)'),
        ('organizational_unit_name', 'Organizational Unit (OU)'),
        ('country_name', 'Country (C)'),
        ('state_or_province_name', 'State/Province (ST)'),
        ('locality_name', 'Locality (L)'),
        ('email_address', 'Email Address'),
    ):
        if cert_data.get(key):
            summary['subject'][label] = cert_data[key]
    for key, label in (
        ('dns_names', 'DNS Names'),
        ('ip_addresses', 'IP Addresses'),
        ('rfc822_names', 'Email Addresses (RFC 822)'),
        ('uris', 'URIs'),
    ):
        if cert_data.get(key):
            summary['san'][label] = cert_data[key]
    parts = [f'{cert_data[unit]} {unit}' for unit in ('days', 'hours', 'minutes', 'seconds') if cert_data.get(unit)]
    summary['validity'] = ', '.join(parts) if parts else _('Not specified')
    return summary


def build_ca_request_data(cert_content_data: dict[str, Any]) -> dict[str, Any]:
    """Build the profile request data used to generate the external CSR."""
    request_data: dict[str, Any] = {
        'subj': {},
        'ext': {'subject_alternative_name': {}},
        'validity': {},
    }
    for field_name in ('common_name', 'organization_name', 'country_name', 'state_or_province_name'):
        value = cert_content_data.get(field_name)
        if value:
            request_data['subj'][field_name] = value
    for field_name in ('dns_names', 'ip_addresses', 'rfc822_names', 'uris'):
        value = cert_content_data.get(field_name)
        if value is not None:
            request_data['ext']['subject_alternative_name'][field_name] = value
    for field_name in ('days', 'hours', 'minutes', 'seconds'):
        value = cert_content_data.get(field_name)
        if value is not None:
            request_data['validity'][field_name] = int(value)
    return request_data
