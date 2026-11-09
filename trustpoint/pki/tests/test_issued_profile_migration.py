# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Exercise profile backfill, blocked upgrades and rollback using historical models."""

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

pytestmark = pytest.mark.django_db(transaction=True)
OLD = [('pki', '0002_initial')]
NEW = [('pki', '0003_issued_credential_certificate_profile')]


@pytest.mark.parametrize('remote', [False, True])
@pytest.mark.parametrize(
    'name_kind', ['unique_name', 'display_name', 'ambiguous', 'name_collision', 'unknown', 'blank']
)
def test_profile_migration_preserves_or_flags_legacy_names(credential_instance, device_instance, name_kind, remote):
    executor = MigrationExecutor(connection)
    executor.migrate(OLD)
    apps = executor.loader.project_state(OLD).apps
    profiles = apps.get_model('pki', 'CertificateProfileModel')
    model_name = 'RemoteIssuedCredentialModel' if remote else 'IssuedCredentialModel'
    records = apps.get_model('pki', model_name)
    profile = profiles.objects.create(unique_name='migration-profile', display_name='Migration Label', profile_json={})
    name = profile.unique_name if name_kind == 'unique_name' else profile.display_name
    if name_kind in {'ambiguous', 'name_collision'}:
        profiles.objects.create(
            unique_name='Migration Label' if name_kind == 'name_collision' else 'other-profile',
            display_name='Migration Label',
            profile_json={},
        )
    elif name_kind == 'unknown':
        name = 'Missing Profile'
    elif name_kind == 'blank':
        name = ''
    record = records.objects.create(
        common_name='legacy-device',
        issued_credential_type=4 if remote else 1,
        credential_id=credential_instance['credential'].pk,
        device_id=device_instance['device'].pk,
        domain_id=device_instance['domain'].pk,
        issued_using_cert_profile=name,
    )
    try:
        if name_kind not in {'unique_name', 'display_name'}:
            with pytest.raises(RuntimeError, match='Resolve missing or ambiguous'):
                MigrationExecutor(connection).migrate(NEW)
            assert records.objects.get(pk=record.pk).issued_using_cert_profile == name
            with connection.cursor() as cursor:
                columns = connection.introspection.get_table_description(cursor, records._meta.db_table)
            assert 'certificate_profile_id' not in {column.name for column in columns}
            # Resolve the saved label explicitly before retrying the atomic migration.
            records.objects.filter(pk=record.pk).update(issued_using_cert_profile=profile.unique_name)
        MigrationExecutor(connection).migrate(NEW)
        new_apps = MigrationExecutor(connection).loader.project_state(NEW).apps
        migrated = new_apps.get_model('pki', model_name).objects.get(pk=record.pk)
        assert migrated.certificate_profile_id == profile.pk
        assert 'issued_using_cert_profile' not in {field.name for field in migrated._meta.fields}
        MigrationExecutor(connection).migrate(OLD)
        restored = records.objects.get(pk=record.pk)
        assert restored.issued_using_cert_profile == profile.display_name
    finally:
        # Leave the database at the current schema even if an assertion fails.
        executor = MigrationExecutor(connection)
        if NEW[0] not in executor.loader.applied_migrations:
            records.objects.filter(pk=record.pk).update(issued_using_cert_profile=profile.unique_name)
        executor.migrate(executor.loader.graph.leaf_nodes())


@pytest.mark.parametrize('label', ['', 'dev_owner_id'])
def test_imported_owner_migration_keeps_profile_empty(credential_instance, label):
    executor = MigrationExecutor(connection)
    executor.migrate(OLD)
    apps = executor.loader.project_state(OLD).apps
    profiles = apps.get_model('pki', 'CertificateProfileModel')
    profiles.objects.create(unique_name='dev_owner_id', profile_json={})
    owner = apps.get_model('pki', 'OwnerCredentialModel').objects.create(
        unique_name='imported-owner',
        owner_credential_type=0,
    )
    records = apps.get_model('pki', 'RemoteIssuedCredentialModel')
    record = records.objects.create(
        common_name='imported-owner',
        issued_credential_type=2,
        owner_credential_id=owner.pk,
        credential_id=credential_instance['credential'].pk,
        issued_using_cert_profile=label,
    )
    try:
        MigrationExecutor(connection).migrate(NEW)
        new_apps = MigrationExecutor(connection).loader.project_state(NEW).apps
        migrated = new_apps.get_model('pki', 'RemoteIssuedCredentialModel').objects.get(pk=record.pk)
        assert migrated.certificate_profile_id is None
        MigrationExecutor(connection).migrate(OLD)
        assert records.objects.get(pk=record.pk).issued_using_cert_profile == ''
    finally:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
