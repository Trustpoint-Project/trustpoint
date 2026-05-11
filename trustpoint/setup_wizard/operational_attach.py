"""Shared bootstrap architecture for attaching to operational state.

This module intentionally contains no handoff side effects. It describes the
contract that both "restore from backup" and "connect to existing instance"
must satisfy before bootstrap may switch into operational runtime.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from typing import Any

import psycopg
from packaging.version import InvalidVersion, Version


class OperationalAttachMode(enum.StrEnum):
    """Bootstrap flows that attach this container to operational state."""

    RESTORE_BACKUP = 'restore_backup'
    CONNECT_EXISTING = 'connect_existing'


class CompatibilitySeverity(enum.StrEnum):
    """Severity of a validation result in the compatibility report."""

    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'


@dataclass(frozen=True, slots=True)
class OperationalDatabaseConfig:
    """Database connection selected in bootstrap for an operational target."""

    host: str
    port: int
    name: str
    user: str
    password: str


@dataclass(frozen=True, slots=True)
class OperationalBackendBinding:
    """Current container binding for a crypto or app-secret backend."""

    backend_kind: str
    profile_name: str | None = None
    details: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class OperationalTargetConfig:
    """Complete attach target selected by the bootstrap wizard."""

    mode: OperationalAttachMode
    database: OperationalDatabaseConfig
    crypto_backend: OperationalBackendBinding
    app_secret_backend: OperationalBackendBinding
    backup_file_name: str | None = None


@dataclass(frozen=True, slots=True)
class OperationalStateSnapshot:
    """Read-only metadata inspected from the operational database/backend."""

    app_version: str | None
    setup_completed: bool
    crypto_backend_kind: str | None
    app_secret_backend_kind: str | None
    managed_key_count: int = 0
    managed_key_binding_count: int = 0
    encrypted_secret_count: int = 0
    app_secret_material_present: bool = False


@dataclass(frozen=True, slots=True)
class CompatibilityCheck:
    """One line in the operator-facing compatibility report."""

    code: str
    label: str
    severity: CompatibilitySeverity
    message: str


@dataclass(frozen=True, slots=True)
class OperationalCompatibilityReport:
    """Read-only validation report shown before explicit attach/apply."""

    mode: OperationalAttachMode
    target: OperationalTargetConfig | None
    snapshot: OperationalStateSnapshot | None
    checks: tuple[CompatibilityCheck, ...]

    @property
    def has_errors(self) -> bool:
        """Return whether any validation check blocks attach/apply."""
        return any(check.severity == CompatibilitySeverity.ERROR for check in self.checks)

    @property
    def can_apply(self) -> bool:
        """Return whether bootstrap may proceed with explicit handoff."""
        return not self.has_errors and self.target is not None and self.snapshot is not None


@dataclass(frozen=True, slots=True)
class TrustpointBackupManifest:
    """Versioned metadata expected in future Trustpoint backup archives."""

    manifest_version: int
    trustpoint_version: str
    database_engine: str
    crypto_backend_kind: str
    app_secret_backend_kind: str
    created_at: str | None = None

    SUPPORTED_MANIFEST_VERSION = 1

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> TrustpointBackupManifest:
        """Parse a Trustpoint backup manifest JSON payload."""
        data = json.loads(payload.decode('utf-8'))
        return cls(
            manifest_version=int(data['manifest_version']),
            trustpoint_version=str(data['trustpoint_version']),
            database_engine=str(data.get('database_engine', 'postgresql')),
            crypto_backend_kind=str(data['crypto_backend_kind']),
            app_secret_backend_kind=str(data['app_secret_backend_kind']),
            created_at=str(data['created_at']) if data.get('created_at') else None,
        )

    def version_check(self, *, current_version: str) -> CompatibilityCheck:
        """Validate manifest and Trustpoint version compatibility."""
        if self.manifest_version != self.SUPPORTED_MANIFEST_VERSION:
            return CompatibilityCheck(
                code='backup_manifest.version_unsupported',
                label='Backup Manifest',
                severity=CompatibilitySeverity.ERROR,
                message=(
                    f'Unsupported backup manifest version {self.manifest_version}; '
                    f'this container supports version {self.SUPPORTED_MANIFEST_VERSION}.'
                ),
            )
        return VersionCompatibilityPolicy(current_version=current_version).check(
            database_version=self.trustpoint_version,
        )


class VersionCompatibilityPolicy:
    """Simple Trustpoint app-version compatibility policy for attach flows."""

    def __init__(self, *, current_version: str) -> None:
        """Initialize the policy with the running container version."""
        self._current_version = current_version

    def check(self, *, database_version: str | None) -> CompatibilityCheck:
        """Compare the database version against the running application."""
        if not database_version:
            return CompatibilityCheck(
                code='version.missing',
                label='Application Version',
                severity=CompatibilitySeverity.ERROR,
                message='The target database does not expose a Trustpoint application version.',
            )

        try:
            current = Version(self._current_version)
            target = Version(database_version)
        except InvalidVersion as exc:
            return CompatibilityCheck(
                code='version.invalid',
                label='Application Version',
                severity=CompatibilitySeverity.ERROR,
                message=f'Could not parse Trustpoint version information: {exc}.',
            )

        if current < target:
            return CompatibilityCheck(
                code='version.container_too_old',
                label='Application Version',
                severity=CompatibilitySeverity.ERROR,
                message=(
                    f'The target database was written by Trustpoint {target}; this container is {current}. '
                    'Start a newer Trustpoint container before attaching.'
                ),
            )

        if current > target:
            return CompatibilityCheck(
                code='version.upgrade_required',
                label='Application Version',
                severity=CompatibilitySeverity.WARNING,
                message=(
                    f'The target database is Trustpoint {target}; this container is {current}. '
                    'Attach may require operational migrations.'
                ),
            )

        return CompatibilityCheck(
            code='version.match',
            label='Application Version',
            severity=CompatibilitySeverity.INFO,
            message=f'The target database version matches this container ({current}).',
        )


class OperationalAttachmentValidator:
    """Build the attach compatibility report from inspected target state."""

    def __init__(self, *, current_version: str) -> None:
        """Initialize validator dependencies."""
        self._version_policy = VersionCompatibilityPolicy(current_version=current_version)

    def build_report(
        self,
        *,
        mode: OperationalAttachMode,
        target: OperationalTargetConfig | None,
        snapshot: OperationalStateSnapshot | None,
    ) -> OperationalCompatibilityReport:
        """Return a compatibility report without mutating bootstrap or operational state."""
        checks: list[CompatibilityCheck] = []

        if target is None:
            checks.append(
                CompatibilityCheck(
                    code='target.missing',
                    label='Target Configuration',
                    severity=CompatibilitySeverity.ERROR,
                    message='No operational target configuration has been staged yet.',
                )
            )

        if snapshot is None:
            checks.append(
                CompatibilityCheck(
                    code='snapshot.missing',
                    label='Target Inspection',
                    severity=CompatibilitySeverity.ERROR,
                    message='The operational target has not been inspected yet.',
                )
            )
            return OperationalCompatibilityReport(mode=mode, target=target, snapshot=snapshot, checks=tuple(checks))

        checks.append(self._version_policy.check(database_version=snapshot.app_version))

        if not snapshot.setup_completed:
            checks.append(
                CompatibilityCheck(
                    code='setup.incomplete',
                    label='Setup State',
                    severity=CompatibilitySeverity.ERROR,
                    message='The target database is not marked as a completed Trustpoint instance.',
                )
            )

        if target is not None:
            checks.extend(self._backend_checks(target=target, snapshot=snapshot))
            checks.extend(self._state_coherence_checks(snapshot=snapshot))

        return OperationalCompatibilityReport(mode=mode, target=target, snapshot=snapshot, checks=tuple(checks))

    @staticmethod
    def _backend_checks(
        *,
        target: OperationalTargetConfig,
        snapshot: OperationalStateSnapshot,
    ) -> tuple[CompatibilityCheck, ...]:
        """Validate configured runtime bindings against the inspected database metadata."""
        checks: list[CompatibilityCheck] = []
        if not snapshot.crypto_backend_kind:
            checks.append(
                CompatibilityCheck(
                    code='crypto.kind_unknown',
                    label='Crypto Backend',
                    severity=CompatibilitySeverity.WARNING,
                    message='The target database does not expose Trustpoint crypto backend metadata yet.',
                )
            )
        elif target.crypto_backend.backend_kind != snapshot.crypto_backend_kind:
            checks.append(
                CompatibilityCheck(
                    code='crypto.kind_mismatch',
                    label='Crypto Backend',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'The database expects crypto backend {snapshot.crypto_backend_kind!r}, but bootstrap '
                        f'configured {target.crypto_backend.backend_kind!r}.'
                    ),
                )
            )
        else:
            checks.append(
                CompatibilityCheck(
                    code='crypto.kind_ok',
                    label='Crypto Backend',
                    severity=CompatibilitySeverity.INFO,
                    message='The configured crypto backend kind matches the target metadata.',
                )
            )

        if not snapshot.app_secret_backend_kind:
            checks.append(
                CompatibilityCheck(
                    code='appsecret.kind_unknown',
                    label='Application Secrets',
                    severity=CompatibilitySeverity.WARNING,
                    message='The target database does not expose Trustpoint application-secret backend metadata yet.',
                )
            )
        elif target.app_secret_backend.backend_kind != snapshot.app_secret_backend_kind:
            checks.append(
                CompatibilityCheck(
                    code='appsecret.kind_mismatch',
                    label='Application Secrets',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'The database expects app-secret backend {snapshot.app_secret_backend_kind!r}, but bootstrap '
                        f'configured {target.app_secret_backend.backend_kind!r}.'
                    ),
                )
            )
        else:
            checks.append(
                CompatibilityCheck(
                    code='appsecret.kind_ok',
                    label='Application Secrets',
                    severity=CompatibilitySeverity.INFO,
                    message='The configured app-secret backend kind matches the target metadata.',
                )
            )

        return tuple(checks)

    @staticmethod
    def _state_coherence_checks(snapshot: OperationalStateSnapshot) -> tuple[CompatibilityCheck, ...]:
        """Validate app-secret and managed-key metadata before attach/apply."""
        checks: list[CompatibilityCheck] = []
        if snapshot.app_secret_material_present:
            checks.append(
                CompatibilityCheck(
                    code='appsecret.material_present',
                    label='Application Secrets',
                    severity=CompatibilitySeverity.INFO,
                    message='The target database contains persisted application-secret material.',
                )
            )
        else:
            checks.append(
                CompatibilityCheck(
                    code='appsecret.material_missing',
                    label='Application Secrets',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        'The target database does not contain persisted application-secret material. '
                        'Attaching could create a new secret root and make existing encrypted data unreadable.'
                    ),
                )
            )

        if snapshot.managed_key_count == 0 and snapshot.managed_key_binding_count == 0:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.none_in_database',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.WARNING,
                    message=(
                        'The target database has no Trustpoint managed-key records. Existing objects on the HSM token '
                        'are not enough by themselves; Trustpoint needs database managed-key records and backend '
                        'bindings to use them.'
                    ),
                )
            )
        elif snapshot.managed_key_binding_count == snapshot.managed_key_count:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.bindings_ok',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.INFO,
                    message='Managed-key records have matching backend binding records.',
                )
            )
        elif snapshot.managed_key_binding_count < snapshot.managed_key_count:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.bindings_missing',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'The target database has {snapshot.managed_key_count} managed keys but only '
                        f'{snapshot.managed_key_binding_count} backend bindings.'
                    ),
                )
            )
        else:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.extra_bindings',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.WARNING,
                    message=(
                        f'The target database has {snapshot.managed_key_count} managed keys but '
                        f'{snapshot.managed_key_binding_count} backend bindings. This may indicate leftover or mixed '
                        'backend state that should be reviewed before attaching.'
                    ),
                )
            )
        return tuple(checks)


class OperationalTargetInspector:
    """Read metadata from an operational PostgreSQL target without mutating it."""

    def inspect_database(self, database: OperationalDatabaseConfig) -> OperationalStateSnapshot:
        """Connect to the target database and return the operational metadata snapshot."""
        with psycopg.connect(
            dbname=database.name,
            user=database.user,
            password=database.password,
            host=database.host,
            port=database.port,
            connect_timeout=5,
        ) as connection:
            with connection.cursor() as cursor:
                app_version = self._read_app_version(cursor)
                crypto_backend_kind = self._read_active_crypto_backend_kind(cursor)
                app_secret_backend_kind = self._read_app_secret_backend_kind(cursor)
                managed_key_count = self._read_count(cursor, table_name='crypto_managed_key')
                managed_key_binding_count = self._read_managed_key_binding_count(
                    cursor,
                    crypto_backend_kind=crypto_backend_kind,
                )
                app_secret_material_present = self._read_app_secret_material_present(
                    cursor,
                    app_secret_backend_kind=app_secret_backend_kind,
                )

        setup_completed = bool(app_version and crypto_backend_kind and app_secret_backend_kind)
        return OperationalStateSnapshot(
            app_version=app_version,
            setup_completed=setup_completed,
            crypto_backend_kind=crypto_backend_kind,
            app_secret_backend_kind=app_secret_backend_kind,
            managed_key_count=managed_key_count,
            managed_key_binding_count=managed_key_binding_count,
            encrypted_secret_count=0,
            app_secret_material_present=app_secret_material_present,
        )

    @classmethod
    def _table_exists(cls, cursor: Any, *, table_name: str) -> bool:
        """Return whether a table exists in the current PostgreSQL schema."""
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = current_schema()
                  AND table_name = %s
            )
            """,
            (table_name,),
        )
        row = cursor.fetchone()
        return bool(row and row[0])

    @classmethod
    def _read_app_version(cls, cursor: Any) -> str | None:
        """Read Trustpoint's persisted application version from the target database."""
        if not cls._table_exists(cursor, table_name='management_appversion'):
            return None
        cursor.execute('SELECT version FROM management_appversion ORDER BY id ASC LIMIT 1')
        row = cursor.fetchone()
        return str(row[0]) if row and row[0] else None

    @classmethod
    def _read_active_crypto_backend_kind(cls, cursor: Any) -> str | None:
        """Read the active crypto backend kind from the target database."""
        if not cls._table_exists(cursor, table_name='crypto_provider_profile'):
            return None
        cursor.execute(
            """
            SELECT backend_kind
            FROM crypto_provider_profile
            WHERE active = TRUE
            ORDER BY id ASC
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        return str(row[0]) if row and row[0] else None

    @classmethod
    def _read_app_secret_backend_kind(cls, cursor: Any) -> str | None:
        """Read the configured application-secret backend kind from the target database."""
        if not cls._table_exists(cursor, table_name='app_secret_backend'):
            return None
        cursor.execute('SELECT backend_kind FROM app_secret_backend WHERE singleton_id = 1 LIMIT 1')
        row = cursor.fetchone()
        return str(row[0]) if row and row[0] else None

    @classmethod
    def _read_count(cls, cursor: Any, *, table_name: str) -> int:
        """Read a table row count when the table exists."""
        if not cls._table_exists(cursor, table_name=table_name):
            return 0
        cursor.execute(f'SELECT COUNT(*) FROM {table_name}')  # noqa: S608 - table name is a fixed caller literal.
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def _read_managed_key_binding_count(cls, cursor: Any, *, crypto_backend_kind: str | None) -> int:
        """Read backend-specific managed-key binding count for reconciliation."""
        table_by_backend = {
            'pkcs11': 'crypto_managed_key_pkcs11_binding',
            'software': 'crypto_managed_key_software_binding',
            'rest': 'crypto_managed_key_rest_binding',
        }
        table_name = table_by_backend.get(crypto_backend_kind or '')
        if table_name is None:
            return 0
        return cls._read_count(cursor, table_name=table_name)

    @classmethod
    def _read_app_secret_material_present(cls, cursor: Any, *, app_secret_backend_kind: str | None) -> bool:
        """Return whether the target DB has persisted material for its app-secret backend."""
        if app_secret_backend_kind == 'software':
            if not cls._table_exists(cursor, table_name='app_secret_software_config'):
                return False
            cursor.execute(
                """
                SELECT raw_dek IS NOT NULL
                FROM app_secret_software_config
                WHERE backend_id = 1
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            return bool(row and row[0])

        if app_secret_backend_kind == 'pkcs11':
            if not cls._table_exists(cursor, table_name='app_secret_pkcs11_config'):
                return False
            cursor.execute(
                """
                SELECT wrapped_dek IS NOT NULL
                FROM app_secret_pkcs11_config
                WHERE backend_id = 1
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            return bool(row and row[0])

        return False
