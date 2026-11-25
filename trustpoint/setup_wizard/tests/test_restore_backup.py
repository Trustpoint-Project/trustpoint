# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for setup-wizard database restore handling."""

from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Self
from unittest.mock import Mock

import pytest
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone

from setup_wizard import backup_restore as views
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_attach import OperationalDatabaseConfig

CUSTOM_DUMP_PAYLOAD = b'PGDMP\x01\x10trustpoint custom dump bytes'
pytestmark = pytest.mark.django_db


def _gzip_payload(payload: bytes = CUSTOM_DUMP_PAYLOAD) -> bytes:
    """Return a gzip-compressed backup payload."""
    return gzip.compress(payload)


def _restore_config(backup_path: Path) -> SetupWizardConfigModel:
    """Build a restore config model pointing at a staged backup path."""
    return SetupWizardConfigModel(
        restore_backup_archive_path=str(backup_path),
        restore_backup_restored_at=timezone.now(),
        operational_db_host='localhost',
        operational_db_port=5432,
        operational_db_name='trustpoint_db',
        operational_db_user='admin',
        operational_db_password='testing321',  # noqa: S106 - test database password value.
    )


def _inspector_with_objects(*, has_objects: bool) -> type:
    """Return an inspector double that reports whether the target has objects."""

    class _Inspector:
        def database_has_objects(self, _target: Any) -> bool:
            return has_objects

    return _Inspector


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


def test_restore_rejects_plain_sql_payloads(monkeypatch: Any, tmp_path: Path) -> None:
    """Plain SQL (and gzipped SQL) payloads are refused; only custom-format dumps are restored."""
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views.subprocess, 'run', _successful_restore_recorder(calls))

    plain_path = tmp_path / 'backup.dump'
    plain_path.write_bytes(b'CREATE TABLE restored(id integer);\n')
    with pytest.raises(DjangoValidationError, match='Plain SQL archives are not accepted'):
        views.restore_operational_database_from_backup(_restore_config(plain_path))

    gzipped_path = tmp_path / 'backup.dump.gz'
    gzipped_path.write_bytes(gzip.compress(b'CREATE TABLE restored(id integer);\n'))
    with pytest.raises(DjangoValidationError, match='Plain SQL archives are not accepted'):
        views.restore_operational_database_from_backup(_restore_config(gzipped_path))

    assert calls == []


def test_restore_refuses_target_with_existing_installation(monkeypatch: Any, tmp_path: Path) -> None:
    """A restore must not overwrite a database that already contains schema objects."""
    backup_path = tmp_path / 'backup.dump.gz'
    backup_path.write_bytes(_gzip_payload())
    config_model = _restore_config(backup_path)
    config_model.restore_backup_restored_at = None
    calls: list[dict[str, Any]] = []

    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views, 'OperationalTargetInspector', _inspector_with_objects(has_objects=True))
    monkeypatch.setattr(views.subprocess, 'run', _successful_restore_recorder(calls))

    with pytest.raises(DjangoValidationError, match='target database is not empty'):
        views.restore_operational_database_from_backup(config_model)

    assert calls == []


def test_restore_allows_an_empty_target(monkeypatch: Any, tmp_path: Path) -> None:
    """A database without schema objects is accepted as a restore target."""
    backup_path = tmp_path / 'backup.dump.gz'
    backup_path.write_bytes(_gzip_payload())
    config_model = _restore_config(backup_path)
    config_model.restore_backup_restored_at = None
    calls: list[dict[str, Any]] = []

    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views, 'OperationalTargetInspector', _inspector_with_objects(has_objects=False))
    monkeypatch.setattr(views.subprocess, 'run', _successful_restore_recorder(calls))

    views.restore_operational_database_from_backup(config_model)

    assert len(calls) == 1


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
        b'DROP TABLE IF EXISTS app_secret_backend;\nCREATE TABLE app_secret_backend(id integer);\n'
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
    stamp = Mock()
    monkeypatch.setattr(views, 'restore_backup_staging_root', lambda: tmp_path)
    monkeypatch.setattr(views.subprocess, 'run', _successful_restore_recorder(calls))
    monkeypatch.setattr(views, '_stamp_restored_app_version', stamp)

    views.restore_operational_database_from_backup(_restore_config(bundle_path))

    assert len(calls) == 1
    assert calls[0]['command'][0] == 'pg_restore'
    assert '--format=custom' in calls[0]['command']
    assert calls[0]['payload'].startswith(b'PGDMP')
    assert not list(tmp_path.glob('extracted-*'))
    assert stamp.call_args.kwargs['version'] == '0.0-test'


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


class _FakeCursor:
    """Minimal psycopg cursor for version-stamping tests."""

    def __init__(self, rows: list[tuple[Any, ...] | None]) -> None:
        self._rows = iter(rows)
        self.statements: list[tuple[str, list[Any] | None]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def execute(self, statement: str, params: list[Any] | None = None) -> None:
        self.statements.append((statement, params))

    def fetchone(self) -> tuple[Any, ...] | None:
        return next(self._rows)


class _FakeConnection:
    """Minimal psycopg connection for version-stamping tests."""

    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def cursor(self) -> _FakeCursor:
        return self._cursor


def _target_database() -> OperationalDatabaseConfig:
    """Return a target config for version-stamping tests."""
    return OperationalDatabaseConfig(
        host='localhost',
        port=5432,
        name='target',
        user='admin',
        password='testing321',  # noqa: S106 - test database password value.
    )


def _run_stamp(monkeypatch: Any, rows: list[tuple[Any, ...] | None]) -> _FakeCursor:
    """Run the stamp helper against a fake database connection."""
    cursor = _FakeCursor(rows)
    monkeypatch.setattr(views.psycopg, 'connect', lambda **_kwargs: _FakeConnection(cursor))
    views._stamp_restored_app_version(database=_target_database(), version='1.2.3')  # noqa: SLF001
    return cursor


def test_stamp_restored_app_version_inserts_missing_row(monkeypatch: Any) -> None:
    """A restored database without a version row gets the verified manifest version."""
    cursor = _run_stamp(monkeypatch, [(1,), None])
    statement, params = cursor.statements[-1]
    assert 'INSERT INTO management_appversion' in statement
    assert params == ['1.2.3', 'restored']


def test_stamp_restored_app_version_keeps_existing_row(monkeypatch: Any) -> None:
    """An existing application-version row is never overwritten."""
    cursor = _run_stamp(monkeypatch, [(1,), (1,)])
    assert not any('INSERT INTO management_appversion' in statement for statement, _ in cursor.statements)


def test_stamp_restored_app_version_skips_missing_table(monkeypatch: Any) -> None:
    """Backups without the application-version table are left untouched."""
    cursor = _run_stamp(monkeypatch, [(None,)])
    assert not any('INSERT INTO management_appversion' in statement for statement, _ in cursor.statements)


def test_stamp_restored_app_version_ignores_invalid_version(monkeypatch: Any) -> None:
    """An invalid manifest version is ignored before any database connection is made."""
    connect = Mock()
    monkeypatch.setattr(views.psycopg, 'connect', connect)
    views._stamp_restored_app_version(database=_target_database(), version='not-a-version')  # noqa: SLF001
    connect.assert_not_called()
