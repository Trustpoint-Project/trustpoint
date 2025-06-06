"""Tests for the settings module."""

import importlib
import os
from pathlib import Path
from unittest import mock

import pytest
from django.apps import apps

# Import the settings module to test its attributes
from trustpoint import settings


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch):
    """Set environment variables for tests."""
    monkeypatch.setenv('DATABASE_ENGINE', 'django.db.backends.postgresql')
    monkeypatch.setenv('DATABASE_NAME', 'test_trustpoint_db')
    monkeypatch.setenv('DATABASE_USER', 'test_user')
    monkeypatch.setenv('DATABASE_PASSWORD', 'test_password')
    monkeypatch.setenv('DATABASE_HOST', 'localhost')
    monkeypatch.setenv('DATABASE_PORT', '5432')


def test_debug_setting():
    """Ensure DEBUG is correctly set for development."""
    assert settings.DEBUG is True, 'DEBUG should be enabled for development.'


def test_database_settings(monkeypatch):
    """Ensure database settings are set correctly."""
    with mock.patch('socket.create_connection') as mock_socket_conn:
        mock_socket_conn.return_value.__enter__ = mock.MagicMock()
        mock_socket_conn.return_value.__exit__ = mock.MagicMock()

        with mock.patch('psycopg.connect') as mock_psycopg:
            mock_psycopg.return_value.__enter__ = mock.MagicMock()
            mock_psycopg.return_value.__exit__ = mock.MagicMock()

            monkeypatch.setattr(settings, 'POSTGRESQL', True)
            monkeypatch.setattr(settings, 'DATABASE_ENGINE', 'django.db.backends.postgresql')
            monkeypatch.setattr(settings, 'DATABASE_HOST', 'localhost')
            monkeypatch.setattr(settings, 'DATABASE_PORT', '5432')
            monkeypatch.setattr(settings, 'DATABASE_NAME', 'test_trustpoint_db')
            monkeypatch.setattr(settings, 'DATABASE_USER', 'test_user')
            monkeypatch.setattr(settings, 'DATABASE_PASSWORD', 'test_password')

            monkeypatch.setattr(settings, 'is_postgre_available', lambda: True)

            importlib.reload(settings)

            databases = settings.DATABASES

            assert databases['default']['ENGINE'] == 'django.db.backends.postgresql', "Database ENGINE should be 'django.db.backends.postgresql'."
            assert databases['default']['NAME'] == 'test_trustpoint_db', "Database NAME should be 'test_trustpoint_db'."
            assert databases['default']['USER'] == 'test_user', "Database USER should be 'test_user'."
            assert databases['default']['PASSWORD'] == 'test_password', "Database PASSWORD should be 'test_password'."
            assert databases['default']['HOST'] == 'localhost', "Database HOST should be 'localhost'."
            assert databases['default']['PORT'] == '5432', "Database PORT should be '5432'."



def test_database_fallback_to_sqlite(monkeypatch):
    """Ensure database falls back to SQLite when PostgreSQL is unavailable."""
    with mock.patch('socket.create_connection', side_effect=OSError):
        with mock.patch('psycopg.connect', side_effect=Exception('Login failed')):
            monkeypatch.setattr(settings, 'POSTGRESQL', True)

            importlib.reload(settings)

            databases = settings.DATABASES

            assert databases['default']['ENGINE'] == 'django.db.backends.sqlite3', 'Database should fall back to SQLite when PostgreSQL is unavailable.'
            assert str(databases['default']['NAME']).endswith('db.sqlite3'), "SQLite database NAME should default to 'db.sqlite3'."

def test_secret_key():
    """Ensure the secret key is defined."""
    assert settings.SECRET_KEY is not None, 'SECRET_KEY must be defined.'
    assert isinstance(settings.SECRET_KEY, str), 'SECRET_KEY must be a string.'


def test_installed_apps():
    """Check if critical apps are installed."""
    expected_apps = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'setup_wizard',
        'users',
        'home',
        'devices',
        'pki',
        'cmp',
        'est',
        'settings',
        'notifications',
    ]

    installed_app_labels = {app_config.name for app_config in apps.get_app_configs()}

    for app in expected_apps:
        assert app in installed_app_labels, f'App {app} should be in INSTALLED_APPS.'



def test_logging_configuration():
    """Ensure logging configuration is properly configured."""
    logging_config = settings.LOGGING

    assert 'handlers' in logging_config, 'Logging configuration must include handlers.'
    assert 'formatters' in logging_config, 'Logging configuration must include formatters.'

    expected_log_file_path = os.path.abspath(str(settings.LOG_FILE_PATH))
    actual_log_file_path = os.path.abspath(
        logging_config['handlers']['rotatingFile']['filename']
    )

    assert actual_log_file_path == expected_log_file_path, (
        f'Log file path should match the defined value in settings. '
        f'Expected: {expected_log_file_path}, Actual: {actual_log_file_path}'
    )


def test_static_and_media_settings():
    """Verify static and media file settings."""
    assert settings.STATIC_URL == 'static/', 'STATIC_URL is not correctly set.'
    assert isinstance(settings.MEDIA_ROOT, Path), 'MEDIA_ROOT should be a Path object.'
    assert str(settings.MEDIA_ROOT).endswith('media'), "MEDIA_ROOT should point to the 'media' directory."


def test_public_paths():
    """Ensure PUBLIC_PATHS is defined and contains expected values."""
    public_paths = settings.PUBLIC_PATHS
    expected_paths = [
        '/setup-wizard',
        '/.well-known/cmp',
        '/.well-known/est',
        '/crl'
    ]
    assert isinstance(public_paths, list), 'PUBLIC_PATHS should be a list.'
    assert public_paths == expected_paths, 'PUBLIC_PATHS should match the defined values.'


def test_language_settings():
    """Verify language and internationalization settings."""
    assert settings.LANGUAGE_CODE == 'en-us', "LANGUAGE_CODE should be 'en-us'."
    assert settings.USE_I18N is True, 'USE_I18N should be enabled.'
    assert settings.USE_TZ is True, 'USE_TZ should be enabled.'
    assert settings.TIME_ZONE == 'UTC', "TIME_ZONE should be set to 'UTC'."
    assert isinstance(settings.LANGUAGES, list), 'LANGUAGES should be a list.'
