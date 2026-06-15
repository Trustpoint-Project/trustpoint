"""Tests for setup-wizard database restore handling."""

from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
from django.core.exceptions import ValidationError as DjangoValidationError

from setup_wizard import views
from setup_wizard.models import SetupWizardConfigModel

CUSTOM_DUMP_PAYLOAD = b'PGDMP\x01\x10trustpoint custom dump bytes'
pytestmark = pytest.mark.django_db


def _gzip_payload(payload: bytes = CUSTOM_DUMP_PAYLOAD) -> bytes:
    """Return a gzip-compressed backup payload."""
    return gzip.compress(payload)


def _restore_config(backup_path: Path) -> SetupWizardConfigModel:
    """Build a restore config model pointing at a staged backup path."""
    return SetupWizardConfigModel(
        restore_backup_archive_path=str(backup_path),
        operational_db_host='localhost',
        operational_db_port=5432,
        operational_db_name='trustpoint_db',
        operational_db_user='admin',
        operational_db_password='testing321',  # noqa: S106 - test database password value.
    )


def _successful_restore_recorder(calls: list[dict[str, Any]]) -> Any:
    """Return a subprocess.run replacement that records restore input."""

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        stdin = kwargs.get('stdin')
        if stdin is not None:
            payload = stdin.read()
        elif command and command[0] == 'pg_restore':
            payload = Path(command[-1]).read_bytes()
        else:
            payload = kwargs.get('input', b'')
        calls.append(
            {
                'command': command,
                'payload': payload,
                'env': kwargs.get('env', {}),
            }
        )
        return subprocess.CompletedProcess(command, 0, stdout=b'', stderr=b'')

    return fake_run


def test_restore_dump_gz_uses_pg_restore_custom_format(monkeypatch: Any, tmp_path: Path) -> None:
    """A gzip-compressed PostgreSQL custom dump is restored through pg_restore custom format."""
    backup_path = tmp_path / 'backup.dump.gz'
    backup_path.write_bytes(_gzip_payload())
    calls: list[dict[str, Any]] = []

    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views.subprocess, 'run', _successful_restore_recorder(calls))

    views.restore_operational_database_from_backup(_restore_config(backup_path))

    assert len(calls) == 1
    assert calls[0]['command'][0] == 'pg_restore'
    assert '--format=custom' in calls[0]['command']
    assert '--clean' in calls[0]['command']
    assert '--if-exists' in calls[0]['command']
    assert '--single-transaction' in calls[0]['command']
    assert calls[0]['payload'].startswith(b'PGDMP')
    assert calls[0]['env']['PGPASSWORD'] == 'testing321'


def test_restore_custom_dump_retries_without_transaction_timeout(monkeypatch: Any, tmp_path: Path) -> None:
    """Custom dumps from newer PostgreSQL versions are retried without transaction_timeout setup."""
    backup_path = tmp_path / 'backup.dump.gz'
    backup_path.write_bytes(_gzip_payload())
    calls: list[dict[str, Any]] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(
            {
                'command': command,
                'input': kwargs.get('input'),
            }
        )
        if command[0] == 'pg_restore' and '--dbname' in command:
            return subprocess.CompletedProcess(
                command,
                1,
                stdout=b'',
                stderr=b'ERROR: unrecognized configuration parameter "transaction_timeout"',
            )
        if command[0] == 'pg_restore' and '--file=-' in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    b'SET transaction_timeout = 0;\n'
                    b'DROP TABLE IF EXISTS app_secret_backend;\n'
                    b'CREATE TABLE app_secret_backend(id integer);\n'
                ),
                stderr=b'',
            )
        return subprocess.CompletedProcess(command, 0, stdout=b'', stderr=b'')

    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views.subprocess, 'run', fake_run)

    views.restore_operational_database_from_backup(_restore_config(backup_path))

    assert [call['command'][0] for call in calls] == ['pg_restore', 'pg_restore', 'psql']
    assert '--clean' in calls[1]['command']
    assert '--if-exists' in calls[1]['command']
    assert '--single-transaction' in calls[2]['command']
    assert calls[2]['input'] == (
        b'DROP TABLE IF EXISTS app_secret_backend;\n'
        b'CREATE TABLE app_secret_backend(id integer);\n'
    )


def test_restore_zip_bundle_extracts_manifest_and_restores_payload(monkeypatch: Any, tmp_path: Path) -> None:
    """A Trustpoint ZIP backup bundle is verified, extracted, and restored as its dump payload."""
    payload = _gzip_payload()
    manifest = {
        'manifest_version': 1,
        'trustpoint_version': '0.0-test',
        'database_engine': 'postgresql',
        'crypto_backend_kind': 'software',
        'app_secret_backend_kind': 'software',
        'backup_format': 'postgres_dump_gzip',
        'encrypted': False,
        'encryption': 'none',
        'payload_sha256': hashlib.sha256(payload).hexdigest(),
        'created_at': '2026-06-12T00:00:00Z',
    }
    bundle_path = tmp_path / 'backup.zip'
    with zipfile.ZipFile(bundle_path, 'w') as archive:
        archive.writestr('backup.dump.gz', payload)
        archive.writestr('backup.dump.gz.manifest.json', json.dumps(manifest).encode('utf-8'))

    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views.subprocess, 'run', _successful_restore_recorder(calls))

    views.restore_operational_database_from_backup(_restore_config(bundle_path))

    assert len(calls) == 1
    assert calls[0]['command'][0] == 'pg_restore'
    assert '--format=custom' in calls[0]['command']
    assert calls[0]['payload'].startswith(b'PGDMP')
    assert not list(tmp_path.glob('extracted-*'))


def test_restore_zip_bundle_rejects_manifest_digest_mismatch(monkeypatch: Any, tmp_path: Path) -> None:
    """A Trustpoint ZIP backup bundle is rejected when the manifest digest does not match."""
    payload = _gzip_payload()
    manifest = {
        'manifest_version': 1,
        'trustpoint_version': '0.0-test',
        'database_engine': 'postgresql',
        'crypto_backend_kind': 'software',
        'app_secret_backend_kind': 'software',
        'backup_format': 'postgres_dump_gzip',
        'encrypted': False,
        'encryption': 'none',
        'payload_sha256': '0' * 64,
        'created_at': '2026-06-12T00:00:00Z',
    }
    bundle_path = tmp_path / 'backup.zip'
    with zipfile.ZipFile(bundle_path, 'w') as archive:
        archive.writestr('backup.dump.gz', payload)
        archive.writestr('backup.dump.gz.manifest.json', json.dumps(manifest).encode('utf-8'))

    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views.subprocess, 'run', _successful_restore_recorder(calls))

    with pytest.raises(DjangoValidationError, match='payload SHA-256'):
        views.restore_operational_database_from_backup(_restore_config(bundle_path))

    assert calls == []
    assert not list(tmp_path.glob('extracted-*'))
