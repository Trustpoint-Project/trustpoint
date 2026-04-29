"""Tests for the settings module."""

import importlib
import os
from pathlib import Path

import pytest
from django.apps import apps

# Import the settings module to test its attributes
from trustpoint import settings


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch):
    """Set environment variables for tests."""
    monkeypatch.setenv('DATABASE_ENGINE', 'django.db.backends.postgresql')
    monkeypatch.setenv('DATABASE_USER', 'test_user')
    monkeypatch.setenv('DATABASE_PASSWORD', 'test_password')
    monkeypatch.setenv('DATABASE_HOST', 'localhost')
    monkeypatch.setenv('DATABASE_PORT', '5432')
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_DATABASE', 'postgresql')
    monkeypatch.delenv('TRUSTPOINT_PHASE', raising=False)
    yield
    monkeypatch.delenv('TRUSTPOINT_PHASE', raising=False)
    monkeypatch.delenv('TRUSTPOINT_OPERATIONAL_DATABASE', raising=False)
    importlib.reload(settings)


def test_debug_setting():
    """Ensure DEBUG tracks the configured container mode."""
    assert settings.DEBUG is (not settings.DOCKER_CONTAINER), 'DEBUG should be the inverse of DOCKER_CONTAINER.'


def test_database_settings(monkeypatch):
    """Ensure operational database settings are explicit and do not probe availability."""
    monkeypatch.setenv('TRUSTPOINT_PHASE', 'operational')
    monkeypatch.setenv('TRUSTPOINT_OPERATIONAL_DATABASE', 'postgresql')
    importlib.reload(settings)

    databases = settings.DATABASES

    assert settings.TRUSTPOINT_PHASE == 'operational'
    assert settings.ROOT_URLCONF == 'trustpoint.urls'
    assert databases['default']['ENGINE'] == 'django.db.backends.postgresql'
    assert databases['default']['USER'] == 'test_user'
    assert databases['default']['PASSWORD'] == 'test_password'
    assert databases['default']['HOST'] == 'localhost'
    assert databases['default']['PORT'] == '5432'


def test_local_development_defaults_to_sqlite(monkeypatch):
    """Ensure local development remains SQLite-backed unless explicitly overridden."""
    monkeypatch.delenv('TRUSTPOINT_PHASE', raising=False)
    monkeypatch.delenv('TRUSTPOINT_OPERATIONAL_DATABASE', raising=False)
    importlib.reload(settings)

    databases = settings.DATABASES

    assert settings.TRUSTPOINT_PHASE == 'operational'
    assert databases['default']['ENGINE'] == 'django.db.backends.sqlite3'
    assert str(databases['default']['NAME']).endswith('db.sqlite3')


def test_bootstrap_database_settings(monkeypatch, tmp_path):
    """Ensure bootstrap uses its own SQLite database and URL surface."""
    bootstrap_db = tmp_path / 'bootstrap.sqlite3'
    monkeypatch.setenv('TRUSTPOINT_PHASE', 'bootstrap')
    monkeypatch.setenv('TRUSTPOINT_BOOTSTRAP_DB_PATH', str(bootstrap_db))
    importlib.reload(settings)

    databases = settings.DATABASES

    assert settings.TRUSTPOINT_PHASE == 'bootstrap'
    assert settings.ROOT_URLCONF == 'trustpoint.urls_bootstrap'
    assert databases['default']['ENGINE'] == 'django.db.backends.sqlite3'
    assert databases['default']['NAME'] == str(bootstrap_db)
    assert 'trustpoint.middleware.Workflow2InlineDrainMiddleware' not in settings.MIDDLEWARE

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
        'crypto',
        'management',
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
        '/.well-known/cmp',
        '/.well-known/est',
        '/rest',
        '/api',
        '/aoki',
        '/crl',
    ]
    assert isinstance(public_paths, list), 'PUBLIC_PATHS should be a list.'
    assert public_paths == expected_paths, 'PUBLIC_PATHS should match the defined values.'


def test_hsm_paths():
    """Verify HSM path defaults are anchored correctly."""
    assert settings.HSM_ROOT == settings.REPO_ROOT / 'var' / 'hsm'
    assert settings.HSM_CONFIG_DIR == settings.HSM_ROOT / 'config'
    assert settings.HSM_LIB_DIR == settings.HSM_ROOT / 'lib'
    assert settings.HSM_TOKEN_DIR == settings.HSM_ROOT / 'tokens'


def test_language_settings():
    """Verify language and internationalization settings."""
    assert settings.LANGUAGE_CODE == 'en-us', "LANGUAGE_CODE should be 'en-us'."
    assert settings.USE_I18N is True, 'USE_I18N should be enabled.'
    assert settings.USE_TZ is True, 'USE_TZ should be enabled.'
    assert settings.TIME_ZONE == 'UTC', "TIME_ZONE should be set to 'UTC'."
    assert isinstance(settings.LANGUAGES, list), 'LANGUAGES should be a list.'
