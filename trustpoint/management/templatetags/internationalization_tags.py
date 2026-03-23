"""Template filters for internationalization formatting."""

from datetime import datetime

from django import template

from management.models import InternationalizationConfig

register = template.Library()


@register.filter
def local_datetime(value: datetime | str | None) -> str:
    """Format datetime using current internationalization settings."""
    if isinstance(value, str):
        return value

    config = InternationalizationConfig.get_current()
    return config.format_datetime(value)
