"""Tests for the WSGI configuration module."""
import os

from django.core.wsgi import get_wsgi_application

from trustpoint.wsgi import application


def test_wsgi_application_initialization() -> None:
    """Test that the WSGI application is initialized correctly."""
    assert os.getenv('DJANGO_SETTINGS_MODULE') == 'trustpoint.settings', \
        "DJANGO_SETTINGS_MODULE should be 'trustpoint.settings'."

    assert callable(application), 'WSGI application should be callable.'

    try:
        wsgi_app = get_wsgi_application()
        assert callable(wsgi_app), (
            'Initializing the WSGI application with `get_wsgi_application` should produce a callable.'
        )
    except Exception as e:
        error_message = f'WSGI application initialization failed. Error: {e}'
        raise AssertionError(error_message)from e
