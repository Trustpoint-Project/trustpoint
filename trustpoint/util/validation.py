"""General validation utilities for Trustpoint."""

import re
from urllib.parse import urlparse


class ValidationError(Exception):
    """Raised when validation fails."""


def validate_common_name_characters(common_name: str) -> None:
    """Validate that the common name contains only safe characters and no URL-like constructs.

    Since common_name is used in workflow contexts that may be interpolated into URLs,
    we restrict to characters that are safe for URL interpolation.
    """
    if not re.match(r'^[a-zA-Z0-9 -]+$', common_name):
        msg = 'Common name can only contain letters, numbers, spaces, and hyphens.'
        raise ValidationError(msg)
    parsed = urlparse(common_name)
    if parsed.scheme or parsed.netloc:
        msg = 'Common name cannot contain URL-like constructs.'
        raise ValidationError(msg)
def validate_application_uri(application_uri: str) -> None:
    """Validate that the application URI has a valid scheme and is not HTTP/HTTPS."""
    parsed = urlparse(application_uri)
    if not parsed.scheme:
        msg = 'Application URI must have a valid scheme.'
        raise ValidationError(msg)

    if parsed.scheme in ('http', 'https'):
        msg = 'HTTP and HTTPS schemes are not allowed for Application URI.'
        raise ValidationError(msg)


def validate_webhook_url(url: str) -> None:
    """Validate that the webhook URL is safe and doesn't allow SSRF attacks."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        msg = 'Webhook URL must be a valid URL with scheme and host.'
        raise ValidationError(msg)

    if parsed.scheme not in ('http', 'https'):
        msg = 'Webhook URL must use HTTP or HTTPS scheme.'
        raise ValidationError(msg)
