# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Verify encryption and decryption preserve existing values in a separate database."""

import os
import sys
from pathlib import Path


def main():
    root = Path(sys.argv[1])
    key = root / 'software-kek'
    signing_key = root / 'django-key'
    signing_key.write_text('synthetic-migration-signing-key')
    os.environ.update(
        DJANGO_SETTINGS_MODULE='trustpoint.settings',
        DJANGO_SECRET_KEY_FILE=str(signing_key),
        TRUSTPOINT_PHASE='operational',
        TRUSTPOINT_OPERATIONAL_DATABASE='sqlite',
        TRUSTPOINT_OPERATIONAL_SQLITE_PATH=str(root / 'database.sqlite3'),
        TRUSTPOINT_SOFTWARE_KEK_FILE=str(key),
        TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND='false',
    )
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import django

    django.setup()
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    from appsecrets.models import AppSecretBackendModel, AppSecretSoftwareConfigModel
    from appsecrets.service import AppSecretConfigurationError, SoftwareAppSecretService
    from onboarding.models import NoOnboardingConfigModel

    def migrate(targets):
        executor = MigrationExecutor(connection)
        executor.migrate(targets)
        return executor.loader.project_state(targets).apps

    latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
    previous = [(app, '0002_initial' if app == 'onboarding' else name) for app, name in latest]
    old_apps = migrate(previous)
    migrate(latest)
    assert not AppSecretBackendModel.objects.exists()
    assert not key.exists(), 'Empty installation must not initialize encryption material'
    old_apps = migrate(previous)
    old_config = old_apps.get_model('onboarding', 'NoOnboardingConfigModel')
    inputs = [
        ('', ''),
        ('a' * 128, ' edge spaces '),
        ('tpsec:v1:literal password', 'b' * 128),
        ('🔐' * 128, 'pässwörd'),
    ]
    ids = [
        old_config.objects.create(
            est_password=password,
            cmp_shared_secret=secret,
            est_password_version=7,
            cmp_secret_version=9,
        ).pk
        for password, secret in inputs
    ]
    backend = AppSecretBackendModel.objects.create(backend_kind='software', dek_initialized=True)
    wrapped = SoftwareAppSecretService.wrap_dek(b'\xab' * 32, b'a' * 32)
    AppSecretSoftwareConfigModel.objects.create(backend=backend, wrapped_dek=wrapped)

    try:
        migrate(latest)
    except AppSecretConfigurationError:
        pass
    else:
        raise AssertionError('Missing key must stop the migration')
    assert list(old_config.objects.order_by('pk').values_list('est_password', 'cmp_shared_secret')) == inputs

    key.write_text('ab' * 32)
    migrate(latest)
    assert (
        list(NoOnboardingConfigModel.objects.order_by('pk').values_list('est_password', 'cmp_shared_secret')) == inputs
    )
    assert list(NoOnboardingConfigModel.objects.values_list('est_password_version', 'cmp_secret_version')) == [
        (7, 9)
    ] * len(inputs)
    with connection.cursor() as cursor:
        cursor.execute('SELECT est_password, cmp_shared_secret FROM onboarding_noonboardingconfigmodel ORDER BY id')
        stored = cursor.fetchall()
    assert stored[0] == ('', '')
    assert all(value.startswith('tpsec:v1:') for row in stored[1:] for value in row)
    assert len(stored[1][0]) > 128 and len(stored[2][1]) > 128
    assert stored[2][0] != inputs[2][0], 'Prefix-looking plaintext must also be encrypted'
    assert bytes(AppSecretSoftwareConfigModel.objects.get().wrapped_dek) == wrapped

    key.unlink()
    try:
        migrate(previous)
    except AppSecretConfigurationError:
        pass
    else:
        raise AssertionError('Missing key must stop migration reversal')
    key.write_text('ab' * 32)
    assert NoOnboardingConfigModel.objects.filter(pk__in=ids).count() == len(inputs)
    assert (
        list(NoOnboardingConfigModel.objects.order_by('pk').values_list('est_password', 'cmp_shared_secret')) == inputs
    )
    old_apps = migrate(previous)
    old_config = old_apps.get_model('onboarding', 'NoOnboardingConfigModel')
    assert list(old_config.objects.order_by('pk').values_list('est_password', 'cmp_shared_secret')) == inputs
    connection.close()
    print('PASS credential migration')


if __name__ == '__main__':
    main()
