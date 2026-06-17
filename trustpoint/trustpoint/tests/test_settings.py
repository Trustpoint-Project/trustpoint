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
    monkeypatch.setenv('DATABASE_USER', 'test_user')
    monkeypatch.setenv('DATABASE_PASSWORD', 'test_password')
    monkeypatch.setenv('DATABASE_HOST', 'localhost')
    monkeypatch.setenv('DATABASE_PORT', '5432')


def test_debug_setting():
    """Ensure DEBUG tracks the configured container mode."""
    assert settings.DEBUG is (not settings.DOCKER_CONTAINER), 'DEBUG should be the inverse of DOCKER_CONTAINER.'


def test_tls_addresses_not_set_keeps_default_hosts_and_origins(monkeypatch):
    """Ensure defaults remain unchanged when TLS address variables are not set."""
    monkeypatch.delenv('TP_TLS_IPV4_ADDRESSES', raising=False)
    monkeypatch.delenv('TP_TLS_IPV6_ADDRESSES', raising=False)
    monkeypatch.delenv('TP_TLS_DNS_NAMES', raising=False)

    importlib.reload(settings)

    assert 'localhost' in settings.ALLOWED_HOSTS
    assert '127.0.0.1' in settings.ALLOWED_HOSTS
    assert '[::1]' in settings.ALLOWED_HOSTS
    assert 'http://localhost:8000' in settings.CSRF_TRUSTED_ORIGINS
    assert 'http://127.0.0.1:8000' in settings.CSRF_TRUSTED_ORIGINS


def test_tls_ipv4_addresses_derives_allowed_hosts_and_csrf_origins(monkeypatch):
    """Ensure TP_TLS_IPV4_ADDRESSES entries are parsed into ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS."""
    monkeypatch.setenv('TP_TLS_IPV4_ADDRESSES', '10.10.0.2, 192.168.1.100')
    monkeypatch.setenv('TP_HTTP_PORT', '8080')
    monkeypatch.setenv('TP_HTTPS_PORT', '8443')

    importlib.reload(settings)

    assert '10.10.0.2' in settings.ALLOWED_HOSTS
    assert '192.168.1.100' in settings.ALLOWED_HOSTS

    assert 'http://10.10.0.2:8080' in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://10.10.0.2:8443' in settings.CSRF_TRUSTED_ORIGINS
    assert 'http://192.168.1.100:8080' in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://192.168.1.100:8443' in settings.CSRF_TRUSTED_ORIGINS


def test_tls_ipv6_addresses_derives_allowed_hosts_and_csrf_origins(monkeypatch):
    """Ensure TP_TLS_IPV6_ADDRESSES entries are parsed into ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS."""
    monkeypatch.setenv('TP_TLS_IPV6_ADDRESSES', 'fe80::1, 2001:db8::1')
    monkeypatch.setenv('TP_HTTP_PORT', '80')
    monkeypatch.setenv('TP_HTTPS_PORT', '443')

    importlib.reload(settings)

    assert 'fe80::1' in settings.ALLOWED_HOSTS
    assert '2001:db8::1' in settings.ALLOWED_HOSTS

    assert 'http://[fe80::1]' in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://[fe80::1]' in settings.CSRF_TRUSTED_ORIGINS
    assert 'http://[2001:db8::1]' in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://[2001:db8::1]' in settings.CSRF_TRUSTED_ORIGINS


def test_tls_dns_names_derives_allowed_hosts_and_csrf_origins(monkeypatch):
    """Ensure TP_TLS_DNS_NAMES entries are parsed into ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS."""
    monkeypatch.setenv('TP_TLS_DNS_NAMES', 'trustpoint.local, example.org')
    monkeypatch.setenv('TP_HTTP_PORT', '8080')
    monkeypatch.setenv('TP_HTTPS_PORT', '8443')

    importlib.reload(settings)

    assert 'trustpoint.local' in settings.ALLOWED_HOSTS
    assert '.trustpoint.local' in settings.ALLOWED_HOSTS
    assert 'example.org' in settings.ALLOWED_HOSTS

    assert 'http://trustpoint.local:8080' in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://trustpoint.local:8443' in settings.CSRF_TRUSTED_ORIGINS
    assert 'http://example.org:8080' in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://example.org:8443' in settings.CSRF_TRUSTED_ORIGINS


def test_tls_dns_names_adds_wildcard_for_local_domains(monkeypatch):
    """Ensure .local domains get wildcard subdomain entries in ALLOWED_HOSTS."""
    monkeypatch.setenv('TP_TLS_DNS_NAMES', 'trustpoint.local, other.local')

    importlib.reload(settings)

    assert 'trustpoint.local' in settings.ALLOWED_HOSTS
    assert '.trustpoint.local' in settings.ALLOWED_HOSTS
    assert 'other.local' in settings.ALLOWED_HOSTS
    assert '.other.local' in settings.ALLOWED_HOSTS


def test_tls_addresses_deduplicates_hosts_and_origins(monkeypatch):
    """Ensure repeated TLS address values do not create duplicate entries."""
    monkeypatch.setenv('TP_TLS_IPV4_ADDRESSES', '10.10.0.2, 10.10.0.2')
    monkeypatch.setenv('TP_TLS_DNS_NAMES', 'dup.local, dup.local')

    importlib.reload(settings)

    assert settings.ALLOWED_HOSTS.count('10.10.0.2') == 1
    assert settings.ALLOWED_HOSTS.count('dup.local') == 1
    assert settings.ALLOWED_HOSTS.count('.dup.local') == 1


def test_tls_addresses_handles_default_ports(monkeypatch):
    """Ensure default ports (80/443) are omitted from CSRF_TRUSTED_ORIGINS."""
    monkeypatch.setenv('TP_TLS_IPV4_ADDRESSES', '10.10.0.2')
    monkeypatch.setenv('TP_HTTP_PORT', '80')
    monkeypatch.setenv('TP_HTTPS_PORT', '443')

    importlib.reload(settings)

    assert 'http://10.10.0.2' in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://10.10.0.2' in settings.CSRF_TRUSTED_ORIGINS
    assert 'http://10.10.0.2:80' not in settings.CSRF_TRUSTED_ORIGINS
    assert 'https://10.10.0.2:443' not in settings.CSRF_TRUSTED_ORIGINS


def test_env_bool_uses_default_when_variable_is_missing(monkeypatch):
    """Ensure boolean environment settings keep their default when unset."""
    monkeypatch.delenv('POSTGRESQL', raising=False)

    assert settings._env_bool('POSTGRESQL', default=True) is True
    assert settings._env_bool('POSTGRESQL', default=False) is False


def test_env_bool_uses_default_when_variable_is_blank(monkeypatch):
    """Ensure blank boolean environment settings keep their default."""
    monkeypatch.setenv('EMAIL_USE_TLS', '')

    assert settings._env_bool('EMAIL_USE_TLS', default=True) is True
    assert settings._env_bool('EMAIL_USE_TLS', default=False) is False


def test_env_bool_parses_truthy_values(monkeypatch):
    """Ensure common truthy strings enable boolean settings."""
    for value in ('1', 'true', 'yes', 'on', ' TRUE '):
        monkeypatch.setenv('POSTGRESQL', value)

        assert settings._env_bool('POSTGRESQL', default=False) is True


def test_env_bool_treats_other_values_as_false(monkeypatch):
    """Ensure non-truthy strings disable boolean settings."""
    for value in ('0', 'false', 'no', 'off', 'unexpected'):
        monkeypatch.setenv('POSTGRESQL', value)

        assert settings._env_bool('POSTGRESQL', default=True) is False


def test_env_value_prefers_direct_environment_variable(monkeypatch, tmp_path):
    """Ensure direct environment variables win over Docker secret files."""
    secret_file = tmp_path / 'db_user'
    secret_file.write_text('secret-user\n')
    monkeypatch.setenv('DATABASE_USER', 'env-user')
    monkeypatch.setenv('DATABASE_USER_FILE', str(secret_file))

    assert settings._env_value('DATABASE_USER', 'admin', file_var='DATABASE_USER_FILE') == 'env-user'


def test_env_value_reads_docker_secret_file(monkeypatch, tmp_path):
    """Ensure settings can be loaded from Docker secret files."""
    secret_file = tmp_path / 'db_password'
    secret_file.write_text('secret-password\n')
    monkeypatch.delenv('DATABASE_PASSWORD', raising=False)
    monkeypatch.setenv('DATABASE_PASSWORD_FILE', str(secret_file))

    assert settings._env_value(
        'DATABASE_PASSWORD',
        'testing321',
        file_var='DATABASE_PASSWORD_FILE',
    ) == 'secret-password'


def test_env_value_falls_back_when_secret_file_is_unreadable(monkeypatch, tmp_path):
    """Ensure unreadable Docker secret paths do not break settings import."""
    missing_file = tmp_path / 'missing_secret'
    monkeypatch.delenv('DATABASE_PASSWORD', raising=False)
    monkeypatch.setenv('DATABASE_PASSWORD_FILE', str(missing_file))

    assert settings._env_value(
        'DATABASE_PASSWORD',
        'testing321',
        file_var='DATABASE_PASSWORD_FILE',
    ) == 'testing321'


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
            monkeypatch.setattr(settings, 'DATABASE_USER', 'test_user')
            monkeypatch.setattr(settings, 'DATABASE_PASSWORD', 'test_password')

            monkeypatch.setattr(settings, 'is_postgre_available', lambda: True)

            importlib.reload(settings)

            databases = settings.DATABASES

            assert databases['default']['ENGINE'] == 'django.db.backends.postgresql', "Database ENGINE should be 'django.db.backends.postgresql'."
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
        '/setup-wizard',
        '/devices/browser',
        '/prometheus/'
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
