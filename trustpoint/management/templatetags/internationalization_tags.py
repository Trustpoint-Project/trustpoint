# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Template filters for internationalization formatting."""

from datetime import datetime

from django import template

from management.i18n import format_datetime
from management.i18n_context import get_current_user

register = template.Library()


@register.filter
def local_datetime(value: datetime | str | None) -> str:
    """Format datetime using the authenticated user's internationalization settings."""
    if isinstance(value, str):
        return value

    user = get_current_user()
    if user is not None and user.is_authenticated:
        return format_datetime(
            value,
            date_format=getattr(user, 'date_format', None),
            timezone_name=getattr(user, 'timezone', None),
        )
    return format_datetime(value)
