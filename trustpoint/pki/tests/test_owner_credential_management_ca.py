# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for issuing DevOwnerIDs through a selected management CA."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client
from django.urls import reverse

from crypto.models import CryptoManagedKeyModel
from pki.models import CaModel, CredentialModel, RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import IDevIDReferenceModel
from pki.services.owner_credential import (
    create_pending_dev_owner_id,
    issue_owner_credential_from_management_ca,
)
from pki.tests.managed_ca_helpers import create_managed_root_ca
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db

CONTENT = {
    'common_name': 'owner-device',
    'uris': 'dev-owner:cert:SN-1234_ABCDEF',
    'days': 10,
}


@pytest.fixture(autouse=True)
def _profiles() -> None:
    call_command('create_default_cert_profiles')


def _management_ca() -> CaModel:
    cert, key = create_managed_root_ca('DevOwnerID Management CA')
    credential = CredentialModel.save_managed_key_credential(
        certificate=cert,
        certificate_chain=[],
        credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
        managed_key=CryptoManagedKeyModel.objects.get(pk=key.managed_key_ref.id),
    )
    ca = CaModel(
        unique_name='DevOwnerID Management CA',
        credential=credential,
        ca_type=CaModel.CaTypeChoice.LOCAL_PKCS11,
        ca_role=CaModel.CaRole.MANAGEMENT,
    )
    ca.save()
    ca.chain_truststore = CaModel._create_chain_truststore(ca)  # noqa: SLF001
    ca.save(update_fields=['chain_truststore'])
    return ca


def test_local_management_ca_signs_devownerid() -> None:
    """A local management CA issues the DevOwnerID and stores the IDevID references."""
    ca = _management_ca()
    profile = CertificateProfileModel.objects.get(unique_name='dev_owner_id')
    pending = create_pending_dev_owner_id(ca)

    issue_owner_credential_from_management_ca(
        pending,
        profile,
        CONTENT,
        ca,
        logger=logging.getLogger(__name__),
    )

    pending.refresh_from_db()
    assert pending.credential is not None
    assert pending.credential.certificate is not None
    pending.credential.get_certificate().verify_directly_issued_by(ca.get_certificate())
    assert IDevIDReferenceModel.objects.filter(
        dev_owner_id=pending,
        idevid_ref='dev-owner:cert:SN-1234_ABCDEF',
    ).exists()


def test_method_page_offers_management_ca_and_hides_mtls() -> None:
    """The add page offers management CA issuance and no longer offers EST mTLS."""
    user = get_user_model().objects.create_superuser(username='devowner-select-admin', password='test-password')  # noqa: S106
    client = Client()
    client.force_login(user)

    response = client.get(reverse('devices:zero_touch_credentials-add'))
    content = response.content.decode()

    assert reverse('devices:zero_touch_credentials-add-management-ca') in content
    assert reverse('devices:zero_touch_credentials-add-file_import-pkcs12') in content
    assert reverse('devices:zero_touch_credentials-add-file_import') in content
    assert reverse('devices:zero_touch_credentials-external-csr-key') in content
    assert 'Request via EST' not in content
    assert 'Request via CMP' not in content
    assert 'Mutual TLS authentication' not in content


def test_clm_shows_management_ca_and_issuance_link() -> None:
    """The CLM page shows the management CA and links to the management CA content step."""
    ca = _management_ca()
    owner = create_pending_dev_owner_id(ca)
    user = get_user_model().objects.create_superuser(username='devowner-clm-admin', password='test-password')  # noqa: S106
    client = Client()
    client.force_login(user)

    response = client.get(reverse('devices:zero_touch_credentials-clm', kwargs={'pk': owner.pk}))
    content = response.content.decode()

    assert ca.unique_name in content
    content_url = reverse(
        'devices:zero_touch_credentials-define-cert-content-management-ca', kwargs={'pk': owner.pk}
    )
    assert content_url in content
    assert 'Remote Host' not in content


def test_external_csr_flow_builds_csr_with_default_devownerid_profile() -> None:
    """The CSR flow creates a pending DevOwnerID and stores the uploaded certificate."""
    user = get_user_model().objects.create_superuser(username='devowner-csr-admin', password='test-password')  # noqa: S106
    client = Client()
    client.force_login(user)

    response = client.post(
        reverse('devices:zero_touch_credentials-external-csr-key'),
        {'key_type': 'RSA-2048'},
    )
    assert response.status_code == 302  # noqa: PLR2004
    owner = RemoteIssuedCredentialModel.objects.filter(
        issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID
    ).latest('created_at')
    content_url = reverse('devices:zero_touch_credentials-external-csr-content', kwargs={'pk': owner.pk})
    assert response.url == content_url

    response = client.post(
        content_url,
        {'common_name': 'owner-device', 'uris': 'dev-owner:cert:SN-1234_ABCDEF', 'days': 10},
    )
    assert response.status_code == 302  # noqa: PLR2004
    upload_url = reverse('devices:zero_touch_credentials-external-csr', kwargs={'pk': owner.pk})
    assert response.url == upload_url

    response = client.get(upload_url)
    assert response.status_code == 200  # noqa: PLR2004
    assert response.context['owner_credential'] == owner

    csr_pem = client.session[f'dev_owner_id_external_csr_{owner.pk}']['csr_pem']
    csr = x509.load_pem_x509_csr(csr_pem.encode('ascii'))
    root, root_key = CertificateGenerator.create_root_ca('External DevOwnerID Root')
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
    )
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    issued_cert = builder.sign(root_key, hashes.SHA256())

    response = client.post(
        upload_url,
        {
            'certificate': SimpleUploadedFile('owner.pem', issued_cert.public_bytes(Encoding.PEM)),
            'certificate_chain': SimpleUploadedFile('chain.pem', root.public_bytes(Encoding.PEM)),
        },
    )
    assert response.status_code == 302  # noqa: PLR2004
    assert response.url == reverse('devices:zero_touch_credentials-clm', kwargs={'pk': owner.pk})

    credential = owner.credential
    assert credential.certificate is not None
    assert list(credential.ordered_certificate_chain_queryset.values_list('certificate__common_name', flat=True)) == [
        'External DevOwnerID Root'
    ]


def test_add_view_creates_management_ca_owner_credential() -> None:
    """The add view binds the key type to the selected management CA."""
    ca = _management_ca()
    user = get_user_model().objects.create_superuser(username='devowner-admin', password='test-password')  # noqa: S106
    client = Client()
    client.force_login(user)

    response = client.post(
        reverse('devices:zero_touch_credentials-add-management-ca'),
        {'management_ca': ca.pk},
    )

    assert response.status_code == 302  # noqa: PLR2004
    owner = RemoteIssuedCredentialModel.objects.get(ca=ca)
    assert owner.issued_credential_type == RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID
    assert client.get(reverse('devices:zero_touch_credentials')).status_code == 200  # noqa: PLR2004
    assert (
        client.get(reverse('devices:zero_touch_credentials-details', kwargs={'pk': owner.pk})).status_code
        == 200  # noqa: PLR2004
    )

    content_url = reverse('devices:zero_touch_credentials-define-cert-content-management-ca', kwargs={'pk': owner.pk})
    assert client.get(content_url).status_code == 200  # noqa: PLR2004
    response = client.post(content_url, CONTENT)
    request_url = reverse('devices:zero_touch_credentials-request-cert-management-ca', kwargs={'pk': owner.pk})
    assert response.url == request_url
    assert client.get(request_url).status_code == 200  # noqa: PLR2004
