# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Stage and restore PostgreSQL backup archives for the setup wizard."""

from __future__ import annotations

import contextlib
import gzip
import os
import shutil
import subprocess
import uuid
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError

from management.backup_artifacts import BackupManifestError, backup_manifest_path, verify_backup_manifest

if TYPE_CHECKING:
    from setup_wizard.models import SetupWizardConfigModel

MAX_RESTORE_OUTPUT_LENGTH = 4000
GPG_EXECUTABLE = '/usr/bin/gpg'


def restore_backup_staging_root() -> Path:
    """Return the bootstrap-private directory for staged restore archives."""
    bootstrap_db_path = Path(str(settings.DATABASES['default']['NAME']))
    return bootstrap_db_path.parent / 'restore'


def staged_restore_archive(config_model: SetupWizardConfigModel) -> Path | None:
    """Return the staged restore archive path when it still exists."""
    configured_path = (config_model.restore_backup_archive_path or '').strip()
    if not configured_path:
        return None

    try:
        archive_path = Path(configured_path).resolve(strict=False)
    except (OSError, TypeError, ValueError):
        return None

    staging_root = restore_backup_staging_root().resolve(strict=False)
    if not archive_path.is_relative_to(staging_root) or not archive_path.is_file():
        return None
    return archive_path


def cleanup_staged_restore_archive(config_model: SetupWizardConfigModel) -> None:
    """Remove an obsolete staged restore archive."""
    archive_path = staged_restore_archive(config_model)
    if archive_path is None:
        return
    with contextlib.suppress(OSError):
        archive_path.unlink()


def stage_restore_backup_archive(uploaded_archive: Any) -> str:
    """Persist an uploaded restore archive in bootstrap-private storage."""
    original_name = str(getattr(uploaded_archive, 'name', '')).lower()
    suffixes = ('.dump.gz.gpg', '.dump.gpg', '.zip.gpg', '.dump.gz', '.dump', '.zip', '.gpg')
    suffix = next((value for value in suffixes if original_name.endswith(value)), '.dump')
    staging_root = restore_backup_staging_root()
    staging_root.mkdir(parents=True, exist_ok=True)
    staging_root.chmod(0o700)
    archive_path = staging_root / f'restore-{uuid.uuid4().hex}{suffix}'
    with archive_path.open('wb') as destination:
        for chunk in uploaded_archive.chunks():
            destination.write(chunk)
    archive_path.chmod(0o600)
    return str(archive_path)


def _looks_like_gzip(path: Path) -> bool:
    """Return whether the file starts with the gzip magic bytes."""
    with path.open('rb') as file:
        return file.read(2) == b'\x1f\x8b'


def _looks_like_gpg(path: Path) -> bool:
    """Return whether the file looks like an OpenPGP encrypted payload."""
    with path.open('rb') as file:
        prefix = file.read(64)
    return prefix.startswith(b'-----BEGIN PGP MESSAGE-----') or prefix[:1] in {b'\x85', b'\x8c', b'\x8d'}


def _open_restore_archive(archive_path: Path) -> Any:
    """Open a staged restore archive, transparently decompressing gzip files."""
    if _looks_like_gzip(archive_path):
        return gzip.open(archive_path, 'rb')
    return archive_path.open('rb')


def _restore_archive_is_custom_pg_dump(archive_path: Path) -> bool:
    """Return whether the staged archive is a PostgreSQL custom-format dump."""
    with _open_restore_archive(archive_path) as archive_file:
        return bool(archive_file.read(5) == b'PGDMP')


def _materialize_restore_archive(archive_path: Path) -> Path:
    """Return an uncompressed file that restore subprocesses can read by file descriptor."""
    if not _looks_like_gzip(archive_path):
        return archive_path

    materialized_path = restore_backup_staging_root() / f'pgrestore-{uuid.uuid4().hex}.dump'
    try:
        with gzip.open(archive_path, 'rb') as source, materialized_path.open('wb') as destination:
            shutil.copyfileobj(source, destination)
        materialized_path.chmod(0o600)
    except OSError:
        with contextlib.suppress(OSError):
            materialized_path.unlink()
        raise
    return materialized_path


def _format_restore_process_output(completed_process: subprocess.CompletedProcess[bytes]) -> str:
    """Return bounded restore command output for the wizard."""
    stderr = completed_process.stderr.decode('utf-8', errors='replace').strip() if completed_process.stderr else ''
    stdout = completed_process.stdout.decode('utf-8', errors='replace').strip() if completed_process.stdout else ''
    output = stderr or stdout
    if len(output) > MAX_RESTORE_OUTPUT_LENGTH:
        return output[-MAX_RESTORE_OUTPUT_LENGTH:]
    return output


def _restore_failed_on_transaction_timeout(completed_process: subprocess.CompletedProcess[bytes]) -> bool:
    """Return whether pg_restore failed on a PostgreSQL transaction_timeout SET statement."""
    output = _format_restore_process_output(completed_process)
    return 'unrecognized configuration parameter "transaction_timeout"' in output


def _strip_transaction_timeout_from_plain_restore(sql_payload: bytes) -> bytes:
    """Remove pg_dump's PostgreSQL-17 transaction_timeout SET for older restore targets."""
    filtered_lines = [
        line for line in sql_payload.splitlines(keepends=True) if line.strip() != b'SET transaction_timeout = 0;'
    ]
    return b''.join(filtered_lines)


def _retry_custom_restore_without_transaction_timeout(
    *,
    materialized_restore_path: Path,
    common_args: list[str],
    env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    """Retry a custom dump restore after filtering unsupported transaction_timeout setup."""
    restore_options = ['--clean', '--if-exists', '--no-owner', '--no-privileges']
    dump_to_sql_command = [
        'pg_restore',
        '--format=custom',
        *restore_options,
        '--file=-',
        str(materialized_restore_path),
    ]
    dump_to_sql = subprocess.run(  # noqa: S603
        dump_to_sql_command,
        env=env,
        capture_output=True,
        check=False,
    )
    if dump_to_sql.returncode != 0:
        return dump_to_sql

    filtered_sql = _strip_transaction_timeout_from_plain_restore(dump_to_sql.stdout)
    psql_command = ['psql', '--set', 'ON_ERROR_STOP=1', '--single-transaction', *common_args]
    return subprocess.run(  # noqa: S603
        psql_command,
        input=filtered_sql,
        env=env,
        capture_output=True,
        check=False,
    )


def _decrypt_restore_archive_if_needed(archive_path: Path, backup_password: str) -> Path | None:
    """Decrypt a GPG-encrypted restore archive and return the temporary decrypted file path."""
    if not backup_password:
        return None
    if not _looks_like_gpg(archive_path):
        return None

    archive_name = archive_path.name.lower()
    if archive_name.endswith('.zip.gpg'):
        decrypted_suffix = '.zip'
    elif archive_name.endswith('.gz.gpg'):
        decrypted_suffix = '.dump.gz'
    else:
        decrypted_suffix = '.dump'
    decrypted_path = restore_backup_staging_root() / f'decrypted-{uuid.uuid4().hex}{decrypted_suffix}'
    completed_process = subprocess.run(  # noqa: S603
        [
            GPG_EXECUTABLE,
            '--batch',
            '--yes',
            '--pinentry-mode',
            'loopback',
            '--passphrase-fd',
            '0',
            '--output',
            str(decrypted_path),
            '--decrypt',
            str(archive_path),
        ],
        input=backup_password.encode('utf-8'),
        capture_output=True,
        check=False,
    )
    if completed_process.returncode == 0:
        decrypted_path.chmod(0o600)
        return decrypted_path

    output = _format_restore_process_output(completed_process)
    with contextlib.suppress(OSError):
        decrypted_path.unlink()
    msg = f'Backup archive decryption failed: {output or "gpg failed without output"}'
    raise DjangoValidationError(msg)


def _restore_payload_suffix(filename: str) -> str:
    """Return a safe suffix for an extracted PostgreSQL backup payload."""
    normalized_name = filename.lower()
    if normalized_name.endswith('.dump.gz'):
        return '.dump.gz'
    if normalized_name.endswith('.dump'):
        return '.dump'
    return '.dump'


def _backup_payload_infos(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Return PostgreSQL dump payload members from a Trustpoint backup bundle."""
    payload_infos: list[zipfile.ZipInfo] = []
    for member in archive.infolist():
        if member.is_dir():
            continue
        member_name = Path(member.filename).name.lower()
        if member_name.endswith('.manifest.json'):
            continue
        if member_name.endswith(('.dump', '.dump.gz')):
            payload_infos.append(member)
    return payload_infos


def _extract_restore_bundle_if_needed(archive_path: Path) -> Path | None:
    """Extract a Trustpoint ZIP backup bundle and verify its manifest sidecar."""
    if not zipfile.is_zipfile(archive_path):
        return None

    payload_path: Path | None = None
    manifest_path: Path | None = None
    try:
        with zipfile.ZipFile(archive_path) as backup_bundle:
            payload_infos = _backup_payload_infos(backup_bundle)
            if len(payload_infos) != 1:
                msg = 'Backup bundle must contain exactly one .dump or .dump.gz payload.'
                raise DjangoValidationError(msg)

            payload_info = payload_infos[0]
            payload_name = Path(payload_info.filename).name
            manifest_name = f'{payload_name}.manifest.json'
            manifest_info = next(
                (
                    member
                    for member in backup_bundle.infolist()
                    if not member.is_dir() and Path(member.filename).name == manifest_name
                ),
                None,
            )
            if manifest_info is None:
                msg = f'Backup bundle is missing matching manifest sidecar {manifest_name!r}.'
                raise DjangoValidationError(msg)

            staging_root = restore_backup_staging_root()
            staging_root.mkdir(parents=True, exist_ok=True)
            payload_path = staging_root / f'extracted-{uuid.uuid4().hex}{_restore_payload_suffix(payload_name)}'
            manifest_path = backup_manifest_path(payload_path)

            with backup_bundle.open(payload_info) as source, payload_path.open('wb') as destination:
                shutil.copyfileobj(source, destination)
            with backup_bundle.open(manifest_info) as source, manifest_path.open('wb') as destination:
                shutil.copyfileobj(source, destination)

            payload_path.chmod(0o600)
            manifest_path.chmod(0o600)
            verify_backup_manifest(payload_path)
            return payload_path
    except (BackupManifestError, OSError, zipfile.BadZipFile) as exc:
        for temporary_path in (manifest_path, payload_path):
            if temporary_path is not None:
                with contextlib.suppress(OSError):
                    temporary_path.unlink()
        msg = f'Backup bundle is invalid: {exc}'
        raise DjangoValidationError(msg) from exc


def restore_operational_database_from_backup(
    config_model: SetupWizardConfigModel,
    *,
    backup_password: str = '',
) -> None:
    """Restore the staged backup archive into the configured operational PostgreSQL database."""
    archive_path = staged_restore_archive(config_model)
    if archive_path is None:
        msg = 'No staged restore archive is available.'
        raise DjangoValidationError(msg)
    if _looks_like_gpg(archive_path) and not backup_password:
        msg_0 = 'This backup archive is encrypted. Enter the backup password.'
        raise DjangoValidationError(msg_0)

    decrypted_path: Path | None = None
    extracted_path: Path | None = None
    materialized_restore_path: Path | None = None
    try:
        decrypted_path = _decrypt_restore_archive_if_needed(archive_path, backup_password)
        extracted_path = _extract_restore_bundle_if_needed(decrypted_path or archive_path)
        restore_source_path = extracted_path or decrypted_path or archive_path
        materialized_restore_path = _materialize_restore_archive(restore_source_path)

        env = os.environ.copy()
        env['PGPASSWORD'] = config_model.operational_db_password
        common_args = [
            '--host',
            config_model.operational_db_host,
            '--port',
            str(config_model.operational_db_port),
            '--username',
            config_model.operational_db_user,
            '--dbname',
            config_model.operational_db_name,
        ]
        if _restore_archive_is_custom_pg_dump(materialized_restore_path):
            command = [
                'pg_restore',
                '--format=custom',
                '--exit-on-error',
                '--single-transaction',
                '--clean',
                '--if-exists',
                '--no-owner',
                '--no-privileges',
                *common_args,
                str(materialized_restore_path),
            ]
            completed_process = subprocess.run(  # noqa: S603
                command,
                env=env,
                capture_output=True,
                check=False,
            )
            if completed_process.returncode != 0 and _restore_failed_on_transaction_timeout(completed_process):
                completed_process = _retry_custom_restore_without_transaction_timeout(
                    materialized_restore_path=materialized_restore_path,
                    common_args=common_args,
                    env=env,
                )
        else:
            command = ['psql', '--set', 'ON_ERROR_STOP=1', '--single-transaction', *common_args]
            with materialized_restore_path.open('rb') as archive_file:
                completed_process = subprocess.run(  # noqa: S603
                    command,
                    stdin=archive_file,
                    env=env,
                    capture_output=True,
                    check=False,
                )
    except FileNotFoundError as exception:
        error_message = f'Restore tool not available in this container: {exception.filename}.'
        raise DjangoValidationError(error_message) from exception
    finally:
        temporary_restore_paths = {archive_path, decrypted_path, extracted_path}
        if materialized_restore_path is not None and materialized_restore_path not in temporary_restore_paths:
            with contextlib.suppress(OSError):
                materialized_restore_path.unlink()
        if extracted_path is not None:
            with contextlib.suppress(OSError):
                backup_manifest_path(extracted_path).unlink()
            with contextlib.suppress(OSError):
                extracted_path.unlink()
        if decrypted_path is not None:
            with contextlib.suppress(OSError):
                decrypted_path.unlink()

    if completed_process.returncode == 0:
        return

    output = _format_restore_process_output(completed_process)
    msg = f'Database restore failed: {output or "restore command failed without output"}'
    raise DjangoValidationError(msg)
