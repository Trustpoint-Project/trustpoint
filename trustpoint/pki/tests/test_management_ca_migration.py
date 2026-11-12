# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Preserve DevOwnerID references when removing the legacy owner wrapper."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from django.apps import apps as django_apps
from django.core.management.sql import emit_post_migrate_signal
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from aoki.views import AokiServiceMixin
from pki.models import CertificateModel
from pki.models.credential import IDevIDReferenceModel

# Include the retained legacy table when PostgreSQL cascades the test database flush.
pytestmark = pytest.mark.django_db(
    transaction=True, available_apps=[config.name for config in django_apps.get_app_configs()]
)
OLD = [('pki', '0004_tp_v1_0_1_dev0')]


@pytest.fixture(scope='module', autouse=True)
def restore_post_migrate_data(django_db_setup, django_db_blocker):
    """Restore permissions and content types after the cascading test flush."""
    yield
    with django_db_blocker.unblock():
        emit_post_migrate_signal(verbosity=0, interactive=False, db=connection.alias)


@pytest.mark.parametrize('pinned_certificate', [False, True])
def test_fold_preserves_renewals_with_different_owner_and_credential_ids(pinned_certificate):
    executor = MigrationExecutor(connection)
    executor.migrate(OLD)
    apps = executor.loader.project_state(OLD).apps
    owners = apps.get_model('pki', 'OwnerCredentialModel')
    owner = owners.objects.create(pk=10000, unique_name='renewed-owner')
    issued = apps.get_model('pki', 'RemoteIssuedCredentialModel')
    try:
        credentials = apps.get_model('pki', 'CredentialModel')
        reference = 'dev-owner:uri:urn:device:renewed'
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Renewed owner')])
        rows = []
        for kind in ('expired', 'renewed', 'unrelated', 'no-san', 'domain', 'pending'):
            certificate = None
            if kind != 'pending':
                now = datetime.now(UTC)
                builder = (
                    x509.CertificateBuilder()
                    .subject_name(name)
                    .issuer_name(name)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=5))
                    .not_valid_after(now + timedelta(days=-1 if kind == 'expired' else 5))
                )
                if kind != 'no-san':
                    uri = 'dev-owner:uri:urn:device:other' if kind == 'unrelated' else reference
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False
                    )
                certificate = CertificateModel.save_certificate(builder.sign(key, hashes.SHA256()))
            credential = credentials.objects.create(
                credential_type=3,
                certificate_id=certificate.pk if certificate else None,
                private_key=key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(),
            )
            rows.append(
                issued.objects.create(
                    common_name=kind,
                    issued_credential_type=0 if kind == 'domain' else 2,
                    owner_credential_id=owner.pk,
                    credential_id=credential.pk,
                )
            )
        assert not issued.objects.filter(pk=owner.pk).exists()
        apps.get_model('pki', 'IDevIDReferenceModel').objects.create(
            dev_owner_id_id=owner.pk,
            idevid_ref=reference,
            dev_owner_id_certificate_id=rows[0].credential.certificate_id if pinned_certificate else None,
        )

        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())

        refs = IDevIDReferenceModel.objects.filter(idevid_ref=reference)
        assert set(refs.values_list('dev_owner_id_id', flat=True)) == {rows[0].pk, rows[1].pk}
        assert not refs.filter(dev_owner_id_id__in=[row.pk for row in rows[2:5]]).exists()
        renewed_ref = refs.get(dev_owner_id_id=rows[1].pk)
        assert renewed_ref.dev_owner_id_certificate_id == rows[1].credential.certificate_id
        assert AokiServiceMixin._get_matching_owner_credential(renewed_ref).pk == rows[1].credential_id
        connection.check_constraints()
    finally:
        # The legacy table is retained in the database and is not flushed by Django.
        issued.objects.filter(owner_credential_id=owner.pk).update(owner_credential_id=None)
        owners.objects.filter(pk=owner.pk).delete()
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
