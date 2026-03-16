"""Custom template tags for help pages."""

from django import template
from django.http import HttpRequest
from django.middleware.csrf import get_token
from django.utils.html import format_html
from django.utils.safestring import SafeString

register = template.Library()


@register.filter(name='replace_csrf')
def replace_csrf(value: str, request: HttpRequest) -> SafeString:
    """Replace CSRF_TOKEN_PLACEHOLDER with actual CSRF token.

    Args:
        value: The HTML string containing CSRF_TOKEN_PLACEHOLDER
        request: The HTTP request object

    Returns:
        HTML string with CSRF token inserted
    """
    if 'CSRF_TOKEN_PLACEHOLDER' in value:
        csrf_token = get_token(request)
        csrf_input = format_html('<input type="hidden" name="csrfmiddlewaretoken" value="{}">', csrf_token)
        return SafeString(value.replace('CSRF_TOKEN_PLACEHOLDER', csrf_input))
    return SafeString(value)
