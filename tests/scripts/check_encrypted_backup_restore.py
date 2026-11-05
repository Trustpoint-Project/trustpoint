# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Run through the bootstrap manage.py shell against an empty, disposable PostgreSQL database."""

# ruff: noqa: INP001, T201

import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import psycopg
from django.conf import settings
from packaging.version import Version

from setup_wizard.backup_restore import restore_backup_staging_root, restore_operational_database_from_backup
from setup_wizard.models import SetupWizardConfigModel

assert settings.TRUSTPOINT_IS_BOOTSTRAP
assert settings.POSTGRES_DB == 'trustpoint_encrypted_restore'
config = SetupWizardConfigModel(
    operational_db_host=settings.DATABASE_HOST,
    operational_db_port=int(settings.DATABASE_PORT),
    operational_db_name=settings.POSTGRES_DB,
    operational_db_user=settings.DATABASE_USER,
    operational_db_password=settings.DATABASE_PASSWORD,
)
staging_root = restore_backup_staging_root()
staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
password = 'encrypted-backup-ci-only'  # noqa: S105 - disposable CI backup, not a deployment secret.
with TemporaryDirectory(prefix='encrypted-backup-', dir=staging_root) as directory:
    archive = Path(directory) / 'recovery.dump.gz.gpg'
    subprocess.run(  # noqa: S603 - fixed executable and disposable test files.
        [
            '/usr/bin/gpg',
            '--homedir',
            directory,
            '--batch',
            '--pinentry-mode',
            'loopback',
            '--passphrase-fd',
            '0',
            '--cipher-algo',
            'AES256',
            '--output',
            str(archive),
            '--symmetric',
            str(settings.BACKUP_FILE_PATH / 'recovery.dump.gz'),
        ],
        input=password.encode(),
        check=True,
    )
    config.restore_backup_archive_path = str(archive)
    restore_operational_database_from_backup(config, backup_password=password)

with (
    psycopg.connect(
        host=config.operational_db_host,
        port=config.operational_db_port,
        dbname=config.operational_db_name,
        user=config.operational_db_user,
        password=config.operational_db_password,
    ) as connection,
    connection.cursor() as cursor,
):
    cursor.execute('SELECT EXISTS (SELECT 1 FROM devices_devicemodel)')
    assert cursor.fetchone() == (True,), 'Encrypted restore did not recover demo devices'
    cursor.execute('SELECT version FROM management_appversion WHERE id = 1')
    row = cursor.fetchone()
    assert row is not None, 'Encrypted restore did not recover version metadata'
    assert Version(row[0]) == Version(settings.APP_VERSION), 'Restored version metadata is incorrect'

print('Encrypted backup restore verified with real GPG decryption and PostgreSQL restoration.')
