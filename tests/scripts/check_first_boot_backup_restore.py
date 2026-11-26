# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Check first-boot restores with existing and missing versions, plus the real target guard."""

# ruff: noqa: INP001, T201

import os
import shutil
import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import psycopg
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from packaging.version import Version

from management.backup_artifacts import backup_manifest_path, load_backup_manifest, sha256_file
from setup_wizard.backup_restore import (
    _operational_target,
    restore_backup_staging_root,
    restore_operational_database_from_backup,
)
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_attach import (
    CompatibilitySeverity,
    OperationalAttachMode,
    OperationalTargetInspector,
)
from setup_wizard.views import build_attach_compatibility_report, build_attach_target


def _require_disposable_target() -> None:
    """Refuse to run destructive schema resets outside the disposable CI database."""
    if not settings.TRUSTPOINT_IS_BOOTSTRAP:
        msg = 'The first-boot restore check must run in bootstrap mode.'
        raise RuntimeError(msg)
    if settings.POSTGRES_DB != 'trustpoint_first_boot_restore' or settings.DATABASE_HOST != 'postgres':
        msg = 'The first-boot restore check drops schemas; use only the disposable CI database.'
        raise RuntimeError(msg)


def _version_row(config: SetupWizardConfigModel) -> tuple[str, object]:
    target = _operational_target(config)
    with (
        psycopg.connect(
            host=target.host,
            port=target.port,
            dbname=target.name,
            user=target.user,
            password=target.password,
        ) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute('SELECT version, last_updated FROM management_appversion ORDER BY id ASC LIMIT 1')
        row = cursor.fetchone()
    assert row is not None, 'backup did not include an application version record'
    return str(row[0]), row[1]


def _check_restored_archive(
    *,
    config: SetupWizardConfigModel,
    archive: Path,
    expected_version: str | None,
    expected_check: str,
    expected_severity: CompatibilitySeverity,
) -> None:
    """Reset the scratch target, restore one archive, and validate the resulting report."""
    target = _operational_target(config)
    with (
        psycopg.connect(
            host=target.host,
            port=target.port,
            dbname=target.name,
            user=target.user,
            password=target.password,
        ) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute('DROP SCHEMA public CASCADE')
        cursor.execute('CREATE SCHEMA public')

    config.restore_backup_archive_path = str(archive)
    restore_operational_database_from_backup(config)
    snapshot = OperationalTargetInspector().inspect_database(target)
    assert snapshot.app_version == expected_version
    assert snapshot.setup_marker_present
    assert snapshot.setup_completed
    report = build_attach_compatibility_report(
        config_model=config,
        mode=OperationalAttachMode.RESTORE_BACKUP,
        target=build_attach_target(config, mode=OperationalAttachMode.RESTORE_BACKUP),
        snapshot=snapshot,
    )
    assert report.can_apply, report.checks
    version_check = next((check for check in report.checks if check.code == expected_check), None)
    assert version_check is not None, [check.code for check in report.checks]
    assert version_check.severity == expected_severity
    if expected_version is not None:
        assert _version_row(config)[0] == expected_version


def main() -> None:
    """Restore real backups and validate version recovery, compatibility, and overwrite protection."""
    _require_disposable_target()
    backup_path = settings.BACKUP_FILE_PATH / 'recovery.dump.gz'
    assert backup_path.is_file(), 'first-boot backup is missing'

    pg_dump = shutil.which('pg_dump')
    if pg_dump is None:
        msg = 'pg_dump is not installed in this container.'
        raise RuntimeError(msg)

    staging_root = restore_backup_staging_root()
    staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging_root.chmod(0o700)
    with TemporaryDirectory(prefix='first-boot-', dir=staging_root) as directory:
        archive_path = f'{directory}/recovery.dump.gz'
        shutil.copyfile(backup_path, archive_path)
        config = SetupWizardConfigModel(
            operational_db_host=settings.DATABASE_HOST,
            operational_db_port=int(settings.DATABASE_PORT),
            operational_db_name=settings.POSTGRES_DB,
            operational_db_user=settings.DATABASE_USER,
            operational_db_password=settings.DATABASE_PASSWORD,
            restore_backup_archive_path=str(archive_path),
        )
        restore_operational_database_from_backup(config)
        version, last_updated = _version_row(config)
        assert Version(version) == Version(settings.APP_VERSION)

        snapshot = OperationalTargetInspector().inspect_database(_operational_target(config))
        assert snapshot.setup_marker_present
        assert snapshot.setup_completed

        try:
            restore_operational_database_from_backup(config)
        except DjangoValidationError as exception:
            if 'not empty' not in str(exception):
                raise
        else:
            msg = 'restore into a populated database was not refused'
            raise AssertionError(msg)

        assert _version_row(config) == (version, last_updated)

        # Keep the version table but omit its rows, as in a backup taken before startup stamps a version.
        missing_version_dump = Path(directory) / 'missing-version.dump'
        subprocess.run(  # noqa: S603 - fixed executable and disposable target database.
            [
                pg_dump,
                '--format=custom',
                '--exclude-table-data=public.management_appversion',
                '--host',
                config.operational_db_host,
                '--port',
                str(config.operational_db_port),
                '--username',
                config.operational_db_user,
                '--dbname',
                config.operational_db_name,
                '--file',
                str(missing_version_dump),
            ],
            env={**os.environ, 'PGPASSWORD': config.operational_db_password},
            check=True,
        )
        # An older release than this container, so the stamped value must come from the manifest.
        obsolete_version = '0.0.1'
        manifest = replace(
            load_backup_manifest(backup_path),
            trustpoint_version=obsolete_version,
            backup_format='postgres_dump',
            payload_sha256=sha256_file(missing_version_dump),
        )
        bundle_path = Path(directory) / 'missing-version.zip'
        with zipfile.ZipFile(bundle_path, 'w') as bundle:
            bundle.write(missing_version_dump, missing_version_dump.name)
            bundle.writestr(backup_manifest_path(missing_version_dump).name, manifest.to_json_bytes())

        for archive, expected_version, expected_check, expected_severity in (
            (missing_version_dump, None, 'version.unknown_restore', CompatibilitySeverity.WARNING),
            (bundle_path, obsolete_version, 'version.upgrade_required', CompatibilitySeverity.WARNING),
        ):
            _check_restored_archive(
                config=config,
                archive=archive,
                expected_version=expected_version,
                expected_check=expected_check,
                expected_severity=expected_severity,
            )

    print(
        'First-boot backup restore verified: existing/missing versions, manifest stamping, and non-empty target guard.'
    )


main()
