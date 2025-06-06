"""Tests for the ASGI configuration module."""

import os

from django.core.asgi import get_asgi_application

from trustpoint.asgi import application


def test_asgi_application_initialization():
    """Test that the ASGI application is initialized correctly."""
    assert os.getenv('DJANGO_SETTINGS_MODULE') == 'trustpoint.settings', \
        "DJANGO_SETTINGS_MODULE should be 'trustpoint.settings'."

    assert callable(application), 'ASGI application should be callable.'

    try:
        asgi_app = get_asgi_application()
        assert callable(asgi_app), (
            'Initializing ASGI application with `get_asgi_application` should create a callable.'
        )
    except Exception as e:
        raise AssertionError('ASGI application initialization failed.') from e
