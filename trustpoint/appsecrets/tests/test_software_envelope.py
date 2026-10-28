# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Fail-closed software envelope encryption and restart regression tests."""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from django.db import close_old_connections, connection

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel, AppSecretSoftwareConfigModel
from appsecrets.service import (
    SOFTWARE_DEK_PREFIX,
    AppSecretConfigurationError,
    SoftwareAppSecretService,
    clear_app_secret_cache,
    load_software_kek,
)
from util.encrypted_fields import EncryptedTextField

pytestmark = pytest.mark.django_db


@pytest.fixture
def fresh_service():
    AppSecretBackendModel.objects.all().delete()
    backend = AppSecretBackendModel.objects.create(backend_kind=AppSecretBackendKind.SOFTWARE)
    config = AppSecretSoftwareConfigModel.objects.create(backend=backend)
    return SoftwareAppSecretService(config)


def test_dek_is_random_wrapped_and_shared_after_restart(fresh_service):
    first = fresh_service.require_dek()
    assert len(first) == 32
    config = AppSecretSoftwareConfigModel.objects.get()
    wrapped = bytes(config.wrapped_dek)
    assert wrapped.startswith(SOFTWARE_DEK_PREFIX)
    assert first not in wrapped and load_software_kek() not in wrapped
    assert 'raw_dek' not in {field.name for field in config._meta.fields}
    ciphertext = fresh_service.encrypt_text('test database secret')
    clear_app_secret_cache()
    worker = SoftwareAppSecretService(AppSecretSoftwareConfigModel.objects.get())
    assert worker.require_dek() == first
    assert worker.decrypt_text(ciphertext) == 'test database secret'
    assert worker.encrypt_text('test database secret') != ciphertext
    assert AppSecretBackendModel.objects.get().dek_initialized


def test_field_roundtrip_and_persisted_ciphertext():
    field = EncryptedTextField()
    encoded = field.get_prep_value('protected field')
    assert encoded.startswith('tpsec:v1:')
    assert field.from_db_value(encoded, None, connection) == 'protected field'


@pytest.mark.parametrize('value', ['', ' ', 'ff' * 31, 'ff' * 33, 'gg' * 32, 'ab' * 32 + '\n', 'é' * 64])
def test_invalid_kek_is_rejected_without_initializing(fresh_service, monkeypatch, tmp_path, value):
    key = tmp_path / 'bad-kek'
    key.write_text(value)
    monkeypatch.setenv('TRUSTPOINT_SOFTWARE_KEK_FILE', str(key))
    with pytest.raises(AppSecretConfigurationError):
        fresh_service.require_dek()
    assert AppSecretSoftwareConfigModel.objects.get().wrapped_dek is None
    assert not AppSecretBackendModel.objects.get().dek_initialized


@pytest.mark.parametrize('clear_cache', [True, False])
def test_wrong_or_missing_kek_never_replaces_wrapped_dek(fresh_service, tmp_path, monkeypatch, clear_cache):
    fresh_service.encrypt_text('existing encrypted field')
    original = bytes(AppSecretSoftwareConfigModel.objects.get().wrapped_dek)
    if clear_cache:
        clear_app_secret_cache()
    bad = tmp_path / 'wrong-kek'
    bad.write_text('cd' * 32)
    monkeypatch.setenv('TRUSTPOINT_SOFTWARE_KEK_FILE', str(bad))
    with pytest.raises(AppSecretConfigurationError, match='Incorrect software KEK'):
        fresh_service.require_dek()
    bad.unlink()
    with pytest.raises(AppSecretConfigurationError, match='cannot be read'):
        fresh_service.require_dek()
    assert bytes(AppSecretSoftwareConfigModel.objects.get().wrapped_dek) == original


@pytest.mark.parametrize('mutation', ['missing', 'truncated', 'tampered', 'unsupported'])
def test_invalid_wrapped_dek_is_never_reinitialized(fresh_service, mutation):
    fresh_service.require_dek()
    config = AppSecretSoftwareConfigModel.objects.get()
    wrapped = bytes(config.wrapped_dek)
    broken = {'missing': None, 'truncated': wrapped[:-1],
              'tampered': wrapped[:-1] + bytes([wrapped[-1] ^ 1]),
              'unsupported': wrapped.replace(b':v1:', b':v2:')}[mutation]
    AppSecretSoftwareConfigModel.objects.filter(pk=config.pk).update(wrapped_dek=broken)
    with patch('appsecrets.service.os.urandom', side_effect=AssertionError('must never regenerate')):
        with pytest.raises(AppSecretConfigurationError):
            fresh_service.require_dek()
    assert AppSecretSoftwareConfigModel.objects.get().wrapped_dek == broken


def test_backend_change_cannot_reuse_cached_software_dek(fresh_service):
    fresh_service.require_dek()
    # Bypass model validation to simulate stale process state after external DB modification.
    AppSecretBackendModel.objects.update(backend_kind=AppSecretBackendKind.PKCS11)
    with pytest.raises(AppSecretConfigurationError, match='backend changed'):
        fresh_service.require_dek()


def test_missing_configuration_does_not_recreate_key(fresh_service):
    from appsecrets.service import get_app_secret_service

    fresh_service.require_dek()
    AppSecretSoftwareConfigModel.objects.all().delete()
    with pytest.raises(AppSecretConfigurationError, match='configuration is missing'):
        get_app_secret_service()


def test_independent_fresh_installations_have_different_deks(fresh_service):
    first = fresh_service.require_dek()
    AppSecretBackendModel.objects.all().delete()
    backend = AppSecretBackendModel.objects.create(backend_kind=AppSecretBackendKind.SOFTWARE)
    second = SoftwareAppSecretService(AppSecretSoftwareConfigModel.objects.create(backend=backend)).require_dek()
    assert first != second


def test_kek_read_permission_error_is_actionable(fresh_service):
    with patch('appsecrets.service.Path.open', side_effect=PermissionError('denied')):
        with pytest.raises(AppSecretConfigurationError, match='original readable secret file'):
            fresh_service.require_dek()


@pytest.mark.django_db(transaction=True)
def test_simultaneous_initialization_is_serialized_or_fails_safely():
    AppSecretBackendModel.objects.all().delete()
    backend = AppSecretBackendModel.objects.create(backend_kind=AppSecretBackendKind.SOFTWARE)
    AppSecretSoftwareConfigModel.objects.create(backend=backend)

    def initialize():
        close_old_connections()
        try:
            return SoftwareAppSecretService(AppSecretSoftwareConfigModel.objects.get()).require_dek()
        except AppSecretConfigurationError as exception:
            # SQLite reports lock conflicts rather than honoring SELECT FOR UPDATE.
            assert connection.vendor == 'sqlite'
            assert 'database conflict' in str(exception)
            return None
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda _: initialize(), range(4)))
    # Retrying a conflict uses the winner's wrapped key, never replaces it.
    persisted = SoftwareAppSecretService(AppSecretSoftwareConfigModel.objects.get()).require_dek()
    assert all(value is None or value == persisted for value in outcomes)
    assert AppSecretSoftwareConfigModel.objects.count() == 1


def test_errors_and_logs_never_contain_key_material(fresh_service, caplog, capsys):
    fresh_service.require_dek()
    path = os.environ['TRUSTPOINT_SOFTWARE_KEK_FILE']
    with open(path) as stream:
        material = stream.read()
    with patch('appsecrets.service.Path.open', side_effect=PermissionError('denied')):
        with pytest.raises(AppSecretConfigurationError) as exception:
            fresh_service.require_dek()
    output = capsys.readouterr()
    assert material not in str(exception.value) + caplog.text + output.out + output.err


def test_first_dek_does_not_query_absent_bootstrap_table(fresh_service):
    with patch.object(connection.introspection, 'table_names', return_value=[]):
        assert len(fresh_service.require_dek()) == 32


@pytest.mark.parametrize('backend_kind', ['software', 'pkcs11'])
def test_schema_transition_refuses_pre_1_encrypted_databases(tmp_path, backend_kind):
    """Run the real migration against an isolated historical schema, preserving all old key bytes."""
    import subprocess
    import sys

    script = '''
import os
import django
django.setup()
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
executor=MigrationExecutor(connection)
old=[('appsecrets','0001_initial')]
executor.migrate(old)
apps=executor.loader.project_state(old).apps
kind=os.environ['ENVELOPE_TEST_KIND']
b=apps.get_model('appsecrets','AppSecretBackendModel').objects.create(backend_kind=kind)
if kind=='software':
    cls=apps.get_model('appsecrets','AppSecretSoftwareConfigModel')
    cls.objects.create(backend=b,raw_dek=b'x'*32)
else:
    cls=apps.get_model('appsecrets','AppSecretPkcs11ConfigModel')
    cls.objects.create(backend=b,module_path='/unused.so',auth_source='file',auth_source_ref='/unused-pin',wrapped_dek=b'old-wrapped')
try:
    MigrationExecutor(connection).migrate([('appsecrets','0002_envelope_encryption')])
except RuntimeError as error:
    assert 'fresh database' in str(error)
else:
    raise AssertionError('must refuse pre-1.0 encryption data')
cfg=cls.objects.get()
assert (bytes(cfg.raw_dek)==b'x'*32) if kind=='software' else (bytes(cfg.wrapped_dek)==b'old-wrapped')
'''
    env = {**os.environ, 'TRUSTPOINT_PHASE': 'bootstrap',
           'TRUSTPOINT_BOOTSTRAP_DB_PATH': str(tmp_path / 'historical.sqlite3'),
           'DJANGO_SETTINGS_MODULE': 'trustpoint.settings', 'ENVELOPE_TEST_KIND': backend_kind,
           'PYTHONPATH': str(Path(__file__).resolve().parents[2])}
    result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
