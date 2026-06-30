"""Trustpoint backup artifact helpers."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from django.conf import settings

from appsecrets.models import AppSecretBackendModel
from crypto.models import CryptoProviderProfileModel
from setup_wizard.operational_attach import (
    SUPPORTED_BACKUP_MANIFEST_VERSION,
    TrustpointBackupManifest,
)

if TYPE_CHECKING:
    from pathlib import Path

MANIFEST_SUFFIX = '.manifest.json'
HASH_CHUNK_SIZE = 1024 * 1024


class BackupManifestError(ValueError):
    """Raised when a backup manifest is missing or inconsistent."""


def backup_manifest_path(backup_path: Path) -> Path:
    """Return the manifest sidecar path for a database backup payload."""
    return backup_path.with_name(f'{backup_path.name}{MANIFEST_SUFFIX}')


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest for a file."""
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda: file.read(HASH_CHUNK_SIZE), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_database_engine() -> str:
    """Return the public database engine name used by the backup manifest."""
    engine = cast('str', settings.DATABASES['default']['ENGINE'])
    if 'postgresql' in engine:
        return 'postgresql'
    if 'sqlite' in engine:
        return 'sqlite'
    return engine.rsplit('.', maxsplit=1)[-1]


def _active_crypto_backend_kind() -> str:
    """Return the active crypto backend kind, or ``unconfigured``."""
    backend_kind = (
        CryptoProviderProfileModel.objects.filter(active=True)
        .values_list('backend_kind', flat=True)
        .first()
    )
    return str(backend_kind or 'unconfigured')


def _active_app_secret_backend_kind() -> str:
    """Return the active app-secret backend kind, or ``unconfigured``."""
    backend_kind = (
        AppSecretBackendModel.objects.order_by('singleton_id')
        .values_list('backend_kind', flat=True)
        .first()
    )
    return str(backend_kind or 'unconfigured')


def build_backup_manifest(backup_path: Path) -> TrustpointBackupManifest:
    """Build manifest metadata for a backup payload."""
    if not backup_path.is_file():
        msg = f'Backup payload does not exist: {backup_path}'
        raise FileNotFoundError(msg)

    return TrustpointBackupManifest(
        manifest_version=SUPPORTED_BACKUP_MANIFEST_VERSION,
        trustpoint_version=str(settings.APP_VERSION),
        database_engine=_normalized_database_engine(),
        crypto_backend_kind=_active_crypto_backend_kind(),
        app_secret_backend_kind=_active_app_secret_backend_kind(),
        backup_format='postgres_dump_gzip' if backup_path.name.endswith('.gz') else 'postgres_dump',
        encrypted=False,
        encryption='none',
        payload_sha256=sha256_file(backup_path),
        created_at=datetime.now(UTC).isoformat().replace('+00:00', 'Z'),
    )


def write_backup_manifest(backup_path: Path) -> Path:
    """Write the backup manifest sidecar and return its path."""
    manifest = build_backup_manifest(backup_path)
    manifest_path = backup_manifest_path(backup_path)
    manifest_path.write_bytes(manifest.to_json_bytes() + b'\n')
    return manifest_path


def load_backup_manifest(backup_path: Path) -> TrustpointBackupManifest:
    """Load the manifest sidecar for a backup payload."""
    manifest_path = backup_manifest_path(backup_path)
    if not manifest_path.is_file():
        msg = f'Backup manifest sidecar is missing: {manifest_path}'
        raise BackupManifestError(msg)
    try:
        return TrustpointBackupManifest.from_json_bytes(manifest_path.read_bytes())
    except (KeyError, TypeError, ValueError) as exc:
        msg = f'Backup manifest sidecar is invalid: {manifest_path}'
        raise BackupManifestError(msg) from exc


def verify_backup_manifest(backup_path: Path) -> TrustpointBackupManifest:
    """Verify that a backup payload matches its manifest sidecar."""
    if not backup_path.is_file():
        msg = f'Backup payload does not exist: {backup_path}'
        raise BackupManifestError(msg)

    manifest = load_backup_manifest(backup_path)
    if manifest.manifest_version != SUPPORTED_BACKUP_MANIFEST_VERSION:
        msg = (
            f'Unsupported backup manifest version {manifest.manifest_version}; '
            f'this container supports version {SUPPORTED_BACKUP_MANIFEST_VERSION}.'
        )
        raise BackupManifestError(msg)

    if not manifest.payload_sha256:
        msg = 'Backup manifest does not include a payload SHA-256 digest.'
        raise BackupManifestError(msg)

    actual_digest = sha256_file(backup_path)
    if manifest.payload_sha256.lower() != actual_digest:
        msg = 'Backup manifest payload SHA-256 does not match the backup file.'
        raise BackupManifestError(msg)

    return manifest
