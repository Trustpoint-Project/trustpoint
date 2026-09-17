# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""User-facing date and time formatting helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo

from django.utils import timezone

if TYPE_CHECKING:
    from datetime import datetime


DATE_FORMATS: dict[str, str] = {
    '0': '%d/%m/%Y %H:%M',
    '1': '%m/%d/%Y %H:%M',
    '2': '%d %b %Y %H:%M',
    '3': '%d %b %Y %I:%M %p',
    '4': '%d %B %Y %H:%M:%S',
    '5': '%d %B %Y %I:%M:%S %p',
    '6': '%Y-%m-%d %H:%M:%S',
    '7': '%Y-%m-%dT%H:%M:%S',
}

DEFAULT_DATE_FORMAT = '6'
DEFAULT_TIMEZONE = 'UTC'


def format_datetime(
    value: datetime | None,
    *,
    date_format: str | None = None,
    timezone_name: str | None = None,
) -> str:
    """Format a datetime using a user's date format and timezone."""
    if value is None:
        return ''

    if timezone.is_naive(value):
        value = timezone.make_aware(value, ZoneInfo(DEFAULT_TIMEZONE))

    converted_value = value.astimezone(ZoneInfo(timezone_name or DEFAULT_TIMEZONE))
    selected_format = DATE_FORMATS.get(date_format or DEFAULT_DATE_FORMAT, DATE_FORMATS[DEFAULT_DATE_FORMAT])
    return converted_value.strftime(selected_format)
