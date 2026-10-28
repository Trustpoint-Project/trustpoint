# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify the first stable schema in a dedicated, empty database."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    """Apply the full initial schema without initializing encryption material."""
    root = Path(sys.argv[1])
    key = root / 'software-kek'
    os.environ.update(
        DJANGO_SETTINGS_MODULE='trustpoint.settings',
        TRUSTPOINT_PHASE='operational',
        TRUSTPOINT_OPERATIONAL_DATABASE=os.environ.get('TP_MIGRATION_TEST_DATABASE', 'sqlite'),
        TRUSTPOINT_OPERATIONAL_SQLITE_PATH=str(root / 'database.sqlite3'),
        TRUSTPOINT_SOFTWARE_KEK_FILE=str(key),
        TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND='false',
    )
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import django

    django.setup()
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    from appsecrets.models import AppSecretBackendModel
    from util.encrypted_fields import EncryptedTextField

    executor = MigrationExecutor(connection)
    targets = executor.loader.graph.leaf_nodes()
    plan = executor.migration_plan(targets)
    management_steps = [migration.name for migration, _ in plan if migration.app_label == 'management']
    assert management_steps == ['0001_initial', '0002_initial']
    executor.migrate(targets)
    apps = executor.loader.project_state(targets).apps
    for model_name, fields in (
        ('BackupOptions', ('password', 'private_key', 'key_passphrase')),
        ('SmtpEmailConfig', ('password',)),
    ):
        model = apps.get_model('management', model_name)
        assert all(isinstance(model._meta.get_field(name), EncryptedTextField) for name in fields)
    assert not AppSecretBackendModel.objects.exists()
    assert not key.exists(), 'Schema creation must not initialize encryption material'
    connection.close()
    print('PASS initial schema')


if __name__ == '__main__':
    main()
