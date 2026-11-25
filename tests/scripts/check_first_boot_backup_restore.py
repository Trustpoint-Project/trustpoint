# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Restore a first-boot backup through bootstrap and verify the real target guard."""

# ruff: noqa: INP001, T201

import shutil
from tempfile import TemporaryDirectory

import psycopg
from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from packaging.version import Version

from setup_wizard.backup_restore import (
    restore_backup_staging_root,
    restore_operational_database_from_backup,
)
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_attach import OperationalDatabaseConfig, OperationalTargetInspector


def _target(config: SetupWizardConfigModel) -> OperationalDatabaseConfig:
    return OperationalDatabaseConfig(
        host=config.operational_db_host,
        port=config.operational_db_port,
        name=config.operational_db_name,
        user=config.operational_db_user,
        password=config.operational_db_password,
    )


def _version_row(config: SetupWizardConfigModel) -> tuple[str, object]:
    target = _target(config)
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


def main() -> None:
    """Restore once, inspect the real metadata, then require the guard to refuse a second restore."""
    assert settings.TRUSTPOINT_IS_BOOTSTRAP
    backup_path = settings.BACKUP_FILE_PATH / 'recovery.dump.gz'
    assert backup_path.is_file(), 'first-boot backup is missing'

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

        snapshot = OperationalTargetInspector().inspect_database(_target(config))
        assert snapshot.app_version is not None
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

    print('First-boot backup restore verified: version metadata and non-empty target guard.')


main()
