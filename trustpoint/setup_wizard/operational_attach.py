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

TRUSTPOINT_BACKUP_MANIFEST_PATH = 'trustpoint-backup-manifest.json'
SUPPORTED_BACKUP_MANIFEST_VERSION = 1


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
    managed_key_missing_binding_count: int = 0
    managed_key_binding_issue_count: int = 0
    managed_key_binding_profile_mismatch_count: int = 0
    managed_key_orphan_binding_count: int = 0
    active_crypto_profile_count: int = 1
    encrypted_secret_count: int = 0
    app_secret_material_present: bool = False


@dataclass(frozen=True, slots=True)
class OperationalAppSecretMaterial:
    """Raw app-secret material read from the target database for validation only."""

    backend_kind: str | None
    raw_dek: bytes = b''
    wrapped_dek: bytes = b''
    kek_label: str = 'trustpoint-app-secret-kek'


@dataclass(frozen=True, slots=True)
class OperationalManagedKeyMaterial:
    """Managed-key binding metadata read from the target database for validation only."""

    backend_kind: str
    alias: str
    provider_label: str
    algorithm: str
    public_key_fingerprint_sha256: str
    signing_execution_mode: str
    binding: dict[str, Any]


@dataclass(frozen=True, slots=True)
class OperationalSoftwareBackendMaterial:
    """Software backend config read from the target database for validation only."""

    encryption_source: str
    encryption_source_ref: str
    allow_exportable_private_keys: bool


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

    def with_checks(self, extra_checks: tuple[CompatibilityCheck, ...]) -> OperationalCompatibilityReport:
        """Return a copy with additional compatibility checks appended."""
        return OperationalCompatibilityReport(
            mode=self.mode,
            target=self.target,
            snapshot=self.snapshot,
            checks=(*self.checks, *extra_checks),
        )


@dataclass(frozen=True, slots=True)
class TrustpointBackupManifest:
    """Versioned metadata expected in future Trustpoint backup archives."""

    manifest_version: int
    trustpoint_version: str
    database_engine: str
    crypto_backend_kind: str
    app_secret_backend_kind: str
    backup_format: str = 'postgres_custom'
    encrypted: bool = False
    encryption: str = 'none'
    payload_sha256: str | None = None
    created_at: str | None = None

    SUPPORTED_MANIFEST_VERSION = SUPPORTED_BACKUP_MANIFEST_VERSION

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
            backup_format=str(data.get('backup_format', 'postgres_custom')),
            encrypted=bool(data.get('encrypted', False)),
            encryption=str(data.get('encryption', 'gpg' if data.get('encrypted') else 'none')),
            payload_sha256=str(data['payload_sha256']) if data.get('payload_sha256') else None,
            created_at=str(data['created_at']) if data.get('created_at') else None,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the manifest into the public backup-manifest contract."""
        return {
            'manifest_version': self.manifest_version,
            'trustpoint_version': self.trustpoint_version,
            'database_engine': self.database_engine,
            'crypto_backend_kind': self.crypto_backend_kind,
            'app_secret_backend_kind': self.app_secret_backend_kind,
            'backup_format': self.backup_format,
            'encrypted': self.encrypted,
            'encryption': self.encryption,
            'payload_sha256': self.payload_sha256,
            'created_at': self.created_at,
        }

    def to_json_bytes(self) -> bytes:
        """Serialize the manifest as stable UTF-8 JSON bytes."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':')).encode('utf-8')

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
        if self.database_engine != 'postgresql':
            return CompatibilityCheck(
                code='backup_manifest.database_unsupported',
                label='Backup Manifest',
                severity=CompatibilitySeverity.ERROR,
                message=f'Unsupported backup database engine {self.database_engine!r}; expected postgresql.',
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
        if snapshot.active_crypto_profile_count != 1:
            checks.append(
                CompatibilityCheck(
                    code='crypto.active_profile_count',
                    label='Crypto Backend',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'The target database has {snapshot.active_crypto_profile_count} active crypto provider '
                        'profiles; exactly one active profile is expected.'
                    ),
                )
            )

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
            severity = (
                CompatibilitySeverity.ERROR
                if snapshot.setup_completed or snapshot.encrypted_secret_count
                else CompatibilitySeverity.WARNING
            )
            message = (
                'The target database does not contain persisted application-secret material. '
                'Existing encrypted data may be unreadable.'
                if snapshot.setup_completed or snapshot.encrypted_secret_count
                else (
                    'The target database does not contain persisted application-secret material. '
                    'This is acceptable only for empty or not-yet-initialized databases.'
                )
            )
            checks.append(
                CompatibilityCheck(
                    code='appsecret.material_missing',
                    label='Application Secrets',
                    severity=severity,
                    message=message,
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
        elif snapshot.managed_key_missing_binding_count:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.bindings_missing',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'{snapshot.managed_key_missing_binding_count} managed-key records do not have a '
                        'backend binding row for the configured backend.'
                    ),
                )
            )
        elif snapshot.managed_key_binding_profile_mismatch_count:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.binding_profile_mismatch',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'{snapshot.managed_key_binding_profile_mismatch_count} managed-key bindings point to '
                        'a different provider profile than their managed-key record.'
                    ),
                )
            )
        elif snapshot.managed_key_binding_issue_count:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.binding_payload_invalid',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'{snapshot.managed_key_binding_issue_count} managed-key binding records are missing '
                        'backend identity material.'
                    ),
                )
            )
        elif snapshot.managed_key_orphan_binding_count:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.orphan_bindings',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.ERROR,
                    message=(
                        f'{snapshot.managed_key_orphan_binding_count} backend binding records do not map to a '
                        'managed-key record.'
                    ),
                )
            )
        elif snapshot.managed_key_binding_count == snapshot.managed_key_count:
            checks.append(
                CompatibilityCheck(
                    code='managed_keys.bindings_ok',
                    label='Managed Keys',
                    severity=CompatibilitySeverity.INFO,
                    message=(
                        'Managed-key records have matching backend binding records. Live backend-object '
                        'availability is checked separately from database metadata.'
                    ),
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

    def inspect_managed_key_material(
        self,
        database: OperationalDatabaseConfig,
    ) -> tuple[OperationalManagedKeyMaterial, ...]:
        """Read managed-key binding material needed for live backend reconciliation."""
        with psycopg.connect(
            dbname=database.name,
            user=database.user,
            password=database.password,
            host=database.host,
            port=database.port,
            connect_timeout=5,
        ) as connection, connection.cursor() as cursor:
            crypto_backend_kind = self._read_active_crypto_backend_kind(cursor)
            if crypto_backend_kind is None:
                return ()
            return self._read_managed_key_material(cursor, crypto_backend_kind=crypto_backend_kind)

    def inspect_software_backend_material(
        self,
        database: OperationalDatabaseConfig,
    ) -> OperationalSoftwareBackendMaterial | None:
        """Read active software backend config needed for software-key reconciliation."""
        with psycopg.connect(
            dbname=database.name,
            user=database.user,
            password=database.password,
            host=database.host,
            port=database.port,
            connect_timeout=5,
        ) as connection, connection.cursor() as cursor:
            return self._read_software_backend_material(cursor)

    def inspect_app_secret_material(self, database: OperationalDatabaseConfig) -> OperationalAppSecretMaterial:
        """Read app-secret material needed for pre-attach decryptability validation."""
        with psycopg.connect(
            dbname=database.name,
            user=database.user,
            password=database.password,
            host=database.host,
            port=database.port,
            connect_timeout=5,
        ) as connection, connection.cursor() as cursor:
            app_secret_backend_kind = self._read_app_secret_backend_kind(cursor)
            if app_secret_backend_kind == 'software':  # noqa: S105 - backend kind value, not a secret.
                return OperationalAppSecretMaterial(
                    backend_kind=app_secret_backend_kind,
                    raw_dek=self._read_software_app_secret_dek(cursor),
                )
            if app_secret_backend_kind == 'pkcs11':  # noqa: S105 - backend kind value, not a secret.
                wrapped_dek, kek_label = self._read_pkcs11_app_secret_material(cursor)
                return OperationalAppSecretMaterial(
                    backend_kind=app_secret_backend_kind,
                    wrapped_dek=wrapped_dek,
                    kek_label=kek_label,
                )
            return OperationalAppSecretMaterial(backend_kind=app_secret_backend_kind)

    def inspect_database(self, database: OperationalDatabaseConfig) -> OperationalStateSnapshot:
        """Connect to the target database and return the operational metadata snapshot."""
        with psycopg.connect(
            dbname=database.name,
            user=database.user,
            password=database.password,
            host=database.host,
            port=database.port,
            connect_timeout=5,
        ) as connection, connection.cursor() as cursor:
            app_version = self._read_app_version(cursor)
            active_crypto_profile_count = self._read_active_crypto_profile_count(cursor)
            crypto_backend_kind = self._read_active_crypto_backend_kind(cursor)
            app_secret_backend_kind = self._read_app_secret_backend_kind(cursor)
            managed_key_count = self._read_count(cursor, table_name='crypto_managed_key')
            managed_key_binding_count = self._read_managed_key_binding_count(
                cursor,
                crypto_backend_kind=crypto_backend_kind,
            )
            managed_key_missing_binding_count = self._read_managed_key_missing_binding_count(
                cursor,
                crypto_backend_kind=crypto_backend_kind,
            )
            managed_key_binding_issue_count = self._read_managed_key_binding_issue_count(
                cursor,
                crypto_backend_kind=crypto_backend_kind,
            )
            managed_key_binding_profile_mismatch_count = (
                self._read_managed_key_binding_profile_mismatch_count(
                    cursor,
                    crypto_backend_kind=crypto_backend_kind,
                )
            )
            managed_key_orphan_binding_count = self._read_managed_key_orphan_binding_count(
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
            managed_key_missing_binding_count=managed_key_missing_binding_count,
            managed_key_binding_issue_count=managed_key_binding_issue_count,
            managed_key_binding_profile_mismatch_count=managed_key_binding_profile_mismatch_count,
            managed_key_orphan_binding_count=managed_key_orphan_binding_count,
            active_crypto_profile_count=active_crypto_profile_count,
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
    def _read_active_crypto_profile_count(cls, cursor: Any) -> int:
        """Read how many active crypto provider profiles exist in the target DB."""
        if not cls._table_exists(cursor, table_name='crypto_provider_profile'):
            return 0
        cursor.execute('SELECT COUNT(*) FROM crypto_provider_profile WHERE active = TRUE')
        row = cursor.fetchone()
        return int(row[0]) if row else 0

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
    def _read_managed_key_material(
        cls,
        cursor: Any,
        *,
        crypto_backend_kind: str,
    ) -> tuple[OperationalManagedKeyMaterial, ...]:
        """Read backend-specific managed-key binding rows for live reconciliation."""
        if not cls._table_exists(cursor, table_name='crypto_managed_key'):
            return ()

        if crypto_backend_kind == 'pkcs11':
            return cls._read_pkcs11_managed_key_material(cursor)
        if crypto_backend_kind == 'software':
            return cls._read_software_managed_key_material(cursor)
        if crypto_backend_kind == 'rest':
            return cls._read_rest_managed_key_material(cursor)
        return ()

    @classmethod
    def _read_pkcs11_managed_key_material(cls, cursor: Any) -> tuple[OperationalManagedKeyMaterial, ...]:
        """Read PKCS#11 managed-key bindings from the target database."""
        if not cls._table_exists(cursor, table_name='crypto_managed_key_pkcs11_binding'):
            return ()
        cursor.execute(
            """
            SELECT
                managed_key.alias,
                managed_key.provider_label,
                managed_key.algorithm,
                managed_key.public_key_fingerprint_sha256,
                managed_key.signing_execution_mode,
                binding.key_id_hex
            FROM crypto_managed_key managed_key
            JOIN crypto_managed_key_pkcs11_binding binding
              ON binding.managed_key_id = managed_key.id
            ORDER BY managed_key.alias ASC
            """
        )
        return tuple(
            OperationalManagedKeyMaterial(
                backend_kind='pkcs11',
                alias=str(row[0]),
                provider_label=str(row[1] or ''),
                algorithm=str(row[2]),
                public_key_fingerprint_sha256=str(row[3]),
                signing_execution_mode=str(row[4]),
                binding={'key_id_hex': str(row[5])},
            )
            for row in cursor.fetchall()
        )

    @classmethod
    def _read_software_managed_key_material(cls, cursor: Any) -> tuple[OperationalManagedKeyMaterial, ...]:
        """Read software managed-key bindings from the target database."""
        if not cls._table_exists(cursor, table_name='crypto_managed_key_software_binding'):
            return ()
        cursor.execute(
            """
            SELECT
                managed_key.alias,
                managed_key.provider_label,
                managed_key.algorithm,
                managed_key.public_key_fingerprint_sha256,
                managed_key.signing_execution_mode,
                binding.key_handle,
                binding.encrypted_private_key_pkcs8_der,
                binding.encryption_metadata
            FROM crypto_managed_key managed_key
            JOIN crypto_managed_key_software_binding binding
              ON binding.managed_key_id = managed_key.id
            ORDER BY managed_key.alias ASC
            """
        )
        return tuple(
            OperationalManagedKeyMaterial(
                backend_kind='software',
                alias=str(row[0]),
                provider_label=str(row[1] or ''),
                algorithm=str(row[2]),
                public_key_fingerprint_sha256=str(row[3]),
                signing_execution_mode=str(row[4]),
                binding={
                    'key_handle': str(row[5]),
                    'encrypted_private_key_pkcs8_der': bytes(row[6] or b''),
                    'encryption_metadata': dict(row[7] or {}),
                },
            )
            for row in cursor.fetchall()
        )

    @classmethod
    def _read_rest_managed_key_material(cls, cursor: Any) -> tuple[OperationalManagedKeyMaterial, ...]:
        """Read REST managed-key bindings from the target database."""
        if not cls._table_exists(cursor, table_name='crypto_managed_key_rest_binding'):
            return ()
        cursor.execute(
            """
            SELECT
                managed_key.alias,
                managed_key.provider_label,
                managed_key.algorithm,
                managed_key.public_key_fingerprint_sha256,
                managed_key.signing_execution_mode,
                binding.remote_key_id,
                binding.remote_key_version
            FROM crypto_managed_key managed_key
            JOIN crypto_managed_key_rest_binding binding
              ON binding.managed_key_id = managed_key.id
            ORDER BY managed_key.alias ASC
            """
        )
        return tuple(
            OperationalManagedKeyMaterial(
                backend_kind='rest',
                alias=str(row[0]),
                provider_label=str(row[1] or ''),
                algorithm=str(row[2]),
                public_key_fingerprint_sha256=str(row[3]),
                signing_execution_mode=str(row[4]),
                binding={
                    'remote_key_id': str(row[5]),
                    'remote_key_version': str(row[6] or ''),
                },
            )
            for row in cursor.fetchall()
        )

    @classmethod
    def _read_software_backend_material(cls, cursor: Any) -> OperationalSoftwareBackendMaterial | None:
        """Read active software backend configuration from the target database."""
        if (
            not cls._table_exists(cursor, table_name='crypto_provider_profile')
            or not cls._table_exists(cursor, table_name='crypto_provider_software_config')
        ):
            return None
        cursor.execute(
            """
            SELECT
                software_config.encryption_source,
                software_config.encryption_source_ref,
                software_config.allow_exportable_private_keys
            FROM crypto_provider_profile profile
            JOIN crypto_provider_software_config software_config
              ON software_config.profile_id = profile.id
            WHERE profile.active = TRUE
            ORDER BY profile.id ASC
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if not row:
            return None
        return OperationalSoftwareBackendMaterial(
            encryption_source=str(row[0]),
            encryption_source_ref=str(row[1] or ''),
            allow_exportable_private_keys=bool(row[2]),
        )

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
    def _managed_key_binding_table(cls, *, crypto_backend_kind: str | None) -> str | None:
        """Return the backend-specific managed-key binding table name."""
        table_by_backend = {
            'pkcs11': 'crypto_managed_key_pkcs11_binding',
            'software': 'crypto_managed_key_software_binding',
            'rest': 'crypto_managed_key_rest_binding',
        }
        return table_by_backend.get(crypto_backend_kind or '')

    @classmethod
    def _read_managed_key_missing_binding_count(cls, cursor: Any, *, crypto_backend_kind: str | None) -> int:
        """Read managed keys without a backend-specific binding row."""
        table_name = cls._managed_key_binding_table(crypto_backend_kind=crypto_backend_kind)
        if table_name is None or not cls._table_exists(cursor, table_name='crypto_managed_key'):
            return 0
        if not cls._table_exists(cursor, table_name=table_name):
            return cls._read_count(cursor, table_name='crypto_managed_key')
        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM crypto_managed_key managed_key
            LEFT JOIN {table_name} binding
              ON binding.managed_key_id = managed_key.id
            WHERE binding.managed_key_id IS NULL
            """  # noqa: S608 - table name is selected from fixed literals above.
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def _read_managed_key_binding_profile_mismatch_count(
        cls,
        cursor: Any,
        *,
        crypto_backend_kind: str | None,
    ) -> int:
        """Read bindings whose provider profile disagrees with the owning managed key."""
        table_name = cls._managed_key_binding_table(crypto_backend_kind=crypto_backend_kind)
        if (
            table_name is None
            or not cls._table_exists(cursor, table_name='crypto_managed_key')
            or not cls._table_exists(cursor, table_name=table_name)
        ):
            return 0
        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM {table_name} binding
            JOIN crypto_managed_key managed_key
              ON managed_key.id = binding.managed_key_id
            WHERE binding.provider_profile_id <> managed_key.provider_profile_id
            """  # noqa: S608 - table name is selected from fixed literals above.
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def _read_managed_key_orphan_binding_count(cls, cursor: Any, *, crypto_backend_kind: str | None) -> int:
        """Read backend binding rows without an owning managed-key record."""
        table_name = cls._managed_key_binding_table(crypto_backend_kind=crypto_backend_kind)
        if (
            table_name is None
            or not cls._table_exists(cursor, table_name='crypto_managed_key')
            or not cls._table_exists(cursor, table_name=table_name)
        ):
            return 0
        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM {table_name} binding
            LEFT JOIN crypto_managed_key managed_key
              ON managed_key.id = binding.managed_key_id
            WHERE managed_key.id IS NULL
            """  # noqa: S608 - table name is selected from fixed literals above.
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def _read_managed_key_binding_issue_count(cls, cursor: Any, *, crypto_backend_kind: str | None) -> int:
        """Read backend-specific binding rows that lack provider identity material."""
        table_by_backend = {
            'pkcs11': ('crypto_managed_key_pkcs11_binding', "key_id_hex IS NULL OR key_id_hex = ''"),
            'software': (
                'crypto_managed_key_software_binding',
                "key_handle IS NULL OR key_handle = '' OR encrypted_private_key_pkcs8_der IS NULL",
            ),
            'rest': ('crypto_managed_key_rest_binding', "remote_key_id IS NULL OR remote_key_id = ''"),
        }
        table_config = table_by_backend.get(crypto_backend_kind or '')
        if table_config is None:
            return 0
        table_name, issue_predicate = table_config
        if not cls._table_exists(cursor, table_name=table_name):
            return 0
        cursor.execute(
            f'SELECT COUNT(*) FROM {table_name} WHERE {issue_predicate}'  # noqa: S608 - fixed literals above.
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    @classmethod
    def _read_app_secret_material_present(cls, cursor: Any, *, app_secret_backend_kind: str | None) -> bool:
        """Return whether the target DB has persisted material for its app-secret backend."""
        if app_secret_backend_kind == 'software':  # noqa: S105 - backend kind value, not a secret.
            if not cls._table_exists(cursor, table_name='app_secret_software_config'):
                return False
            cursor.execute(
                """
                SELECT raw_dek IS NOT NULL AND OCTET_LENGTH(raw_dek) = 32
                FROM app_secret_software_config
                WHERE backend_id = 1
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            return bool(row and row[0])

        if app_secret_backend_kind == 'pkcs11':  # noqa: S105 - backend kind value, not a secret.
            if not cls._table_exists(cursor, table_name='app_secret_pkcs11_config'):
                return False
            cursor.execute(
                """
                SELECT wrapped_dek IS NOT NULL AND OCTET_LENGTH(wrapped_dek) > 0
                FROM app_secret_pkcs11_config
                WHERE backend_id = 1
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            return bool(row and row[0])

        return False

    @classmethod
    def _read_software_app_secret_dek(cls, cursor: Any) -> bytes:
        """Read the software app-secret DEK from the target database."""
        if not cls._table_exists(cursor, table_name='app_secret_software_config'):
            return b''
        cursor.execute(
            """
            SELECT raw_dek
            FROM app_secret_software_config
            WHERE backend_id = 1
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        return bytes(row[0] or b'') if row else b''

    @classmethod
    def _read_pkcs11_app_secret_material(cls, cursor: Any) -> tuple[bytes, str]:
        """Read the wrapped DEK and KEK label from the target database."""
        if not cls._table_exists(cursor, table_name='app_secret_pkcs11_config'):
            return b'', 'trustpoint-app-secret-kek'
        cursor.execute(
            """
            SELECT wrapped_dek, kek_label
            FROM app_secret_pkcs11_config
            WHERE backend_id = 1
            LIMIT 1
            """
        )
        row = cursor.fetchone()
        if not row:
            return b'', 'trustpoint-app-secret-kek'
        return bytes(row[0] or b''), str(row[1] or 'trustpoint-app-secret-kek')
