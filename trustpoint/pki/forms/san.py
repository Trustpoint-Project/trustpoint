# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Form error adapters for the shared SAN input normalizers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError

from pki.util.san import SanValidationError, normalize_san_values, parse_ip_addresses

if TYPE_CHECKING:
    import ipaddress

    from django_stubs_ext import StrOrPromise


def clean_ipv4_sans(value: object, *, error_message: StrOrPromise) -> list[ipaddress.IPv4Address]:
    """Parse IPv4 input while retaining the calling form's validation message."""
    try:
        return parse_ip_addresses(value, version=4)
    except SanValidationError as exc:
        raise ValidationError(error_message) from exc


def clean_ipv6_sans(value: object, *, error_message: StrOrPromise) -> list[ipaddress.IPv6Address]:
    """Parse IPv6 input while retaining the calling form's validation message."""
    try:
        return parse_ip_addresses(value, version=6)
    except SanValidationError as exc:
        raise ValidationError(error_message) from exc


def clean_dns_sans(
    value: object,
    *,
    error_message: StrOrPromise,
    allow_wildcard: bool = True,
) -> list[str]:
    """Normalize DNS input using the calling form's wildcard policy and error message."""
    try:
        return normalize_san_values('dns_names', value, allow_wildcard=allow_wildcard)
    except SanValidationError as exc:
        raise ValidationError(error_message) from exc
