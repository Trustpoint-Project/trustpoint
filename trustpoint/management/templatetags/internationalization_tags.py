from datetime import datetime

from django import template

from management.models import InternationalizationConfig

register = template.Library()


@register.filter
def local_datetime(value):
    """Format datetime using current internationalization settings."""
    if value in (None, ''):
        return ''

    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value

    config = InternationalizationConfig.get_current()
    return config.format_datetime(value)