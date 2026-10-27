# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Normalization of user-supplied SAN values without DNS lookups or profile policy."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Literal, overload
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_noop as _

if TYPE_CHECKING:
    from collections.abc import Sequence

SAN_FIELDS = ('dns_names', 'ip_addresses', 'rfc822_names', 'uris')
MAX_DNS_NAME_LENGTH = 253
_INVALID_URI_CHARACTER = re.compile(r"[^A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]")
_INVALID_PERCENT_ESCAPE = re.compile(r'%(?![0-9A-Fa-f]{2})')
_DNS_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


class SanValidationError(ValueError):
    """A SAN input cannot be represented as a supported certificate identity."""


def split_san_values(value: object) -> list[str]:
    """Trim CSV or list input, dropping empty entries while preserving order and duplicates.

    List entries are not split again: a URI or quoted mailbox may contain commas.
    IP address objects are accepted for existing internal form/request callers.
    """
    values: Sequence[object]
    if value is None:
        return []
    if isinstance(value, str):
        values = value.split(',')
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        msg = _('SAN values must be a comma-separated string or a list of strings.')
        raise SanValidationError(msg)
    result = []
    for entry in values:
        item = entry
        if isinstance(item, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            item = str(item)
        if not isinstance(item, str):
            msg = _('SAN entries must be strings.')
            raise SanValidationError(msg)
        if item.strip():
            result.append(item.strip())
    return result


def normalize_dns_name(value: str, *, allow_wildcard: bool = True) -> str:
    """Convert DNS names to lowercase A-labels; allow only a complete leftmost wildcard."""
    msg = _('Contains an invalid DNS name.')
    wildcard = value.startswith('*.') and allow_wildcard
    host = value[2:] if wildcard else value
    try:
        normalized = host.removesuffix('.').encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise SanValidationError(msg) from exc
    result = '*.' + normalized if wildcard else normalized
    if (
        not normalized
        or len(result) > MAX_DNS_NAME_LENGTH
        or any(not _DNS_LABEL.fullmatch(label) for label in normalized.split('.'))
    ):
        raise SanValidationError(msg)
    return result


@overload
def parse_ip_addresses(value: object, *, version: Literal[4]) -> list[ipaddress.IPv4Address]: ...


@overload
def parse_ip_addresses(value: object, *, version: Literal[6]) -> list[ipaddress.IPv6Address]: ...


@overload
def parse_ip_addresses(
    value: object, *, version: None = None
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]: ...


def parse_ip_addresses(
    value: object,
    *,
    version: Literal[4, 6] | None = None,
) -> list[ipaddress.IPv4Address] | list[ipaddress.IPv6Address] | list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse individual IP identities, including mixed IPv6 notation, without networks or zone IDs."""
    addresses = []
    for item in split_san_values(value):
        try:
            address = ipaddress.ip_address(item)
        except ValueError as exc:
            msg = _('Contains an invalid IP address.')
            raise SanValidationError(msg) from exc
        if '%' in item or (version is not None and address.version != version):
            msg = _('Contains an invalid IP address.')
            raise SanValidationError(msg)
        addresses.append(address)
    return addresses


def normalize_email_name(value: str) -> str:
    """Normalize mailbox domains to A-labels while preserving the local part's case."""
    msg = _('Contains an invalid email address.')
    local, separator, domain = value.rpartition('@')
    try:
        domain = domain if domain.startswith('[') else normalize_dns_name(domain, allow_wildcard=False)
        normalized = local + separator + domain
        normalized.encode('ascii')
        validate_email(normalized)
    except (ValueError, UnicodeError, ValidationError) as exc:
        raise SanValidationError(msg) from exc
    return normalized


def normalize_uri_name(value: str) -> str:
    """Validate an absolute ASCII URI without rewriting case-sensitive identity components."""
    msg = _('Contains an invalid URI.')
    try:
        value.encode('ascii')
        parsed = urlsplit(value)
        _port = parsed.port  # Validate a supplied authority's port as well as bracket syntax.
    except (ValueError, UnicodeError) as exc:
        raise SanValidationError(msg) from exc
    if (
        not parsed.scheme
        or not value.partition(':')[2]
        or _INVALID_URI_CHARACTER.search(value)
        or _INVALID_PERCENT_ESCAPE.search(value)
        or (parsed.scheme in ('http', 'https') and not parsed.hostname)
        or (parsed.netloc and not parsed.hostname)
    ):
        raise SanValidationError(msg)
    return value


def normalize_san_values(field: str, value: object, *, allow_wildcard: bool = True) -> list[str]:
    """Normalize a supported SAN field from either CSV or a list."""
    if field == 'ip_addresses':
        return [str(address) for address in parse_ip_addresses(value)]
    values = split_san_values(value)
    if field == 'dns_names':
        return [normalize_dns_name(item, allow_wildcard=allow_wildcard) for item in values]
    if field == 'rfc822_names':
        return [normalize_email_name(item) for item in values]
    if field == 'uris':
        return [normalize_uri_name(item) for item in values]
    msg = f'Unsupported SAN field: {field}.'
    raise SanValidationError(msg)
