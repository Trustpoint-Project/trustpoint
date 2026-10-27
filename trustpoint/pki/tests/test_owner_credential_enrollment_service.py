# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Remote enrollment keeps the pending key and applies only the selected role's updates."""

import datetime
import logging
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from pki.models import OwnerCredentialModel, RemoteIssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.credential import CredentialModel, IDevIDReferenceModel, PrimaryCredentialCertificate
from pki.services.owner_credential import create_pending_owner_credential, enroll_owner_credential_est
from request.clients import EstClientError
from request.request_context import EstCertificateRequestContext


@pytest.fixture(params=[False, True], ids=['devownerid', 'domain'])
def enrollment(request):
    domain = request.param
    owner = OwnerCredentialModel.objects.create(unique_name='remote-owner', key_type='ECC-SECP256R1')
    profile = CertificateProfileModel.objects.create(
        unique_name='original-profile', profile_json={'type': 'cert_profile'}
    )
    kind = RemoteIssuedCredentialModel.RemoteIssuedCredentialType
    credential_kind = CredentialModel.CredentialTypeChoice
    pending = create_pending_owner_credential(
        owner,
        profile,
        kind.DOMAIN_CREDENTIAL if domain else kind.DEV_OWNER_ID,
        credential_kind.ISSUED_CREDENTIAL if domain else credential_kind.DEV_OWNER_ID,
    )
    context = EstCertificateRequestContext(
        protocol='est',
        operation='simpleenroll',
        domain=None,
        cert_profile_str='selected-profile',
    )
    return domain, owner, pending, context


def test_success_reuses_pending_key_and_preserves_role_specific_updates(enrollment):
    domain, owner, pending, context = enrollment
    credential = pending.credential
    private_pem = credential.get_private_key_serializer().as_pkcs8_pem()
    key = credential.get_private_key()
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'issued-owner')])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(42)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier('dev-owner:device-one')]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    with (
        patch('pki.services.owner_credential.ProfileAwareCsrBuilder') as builder,
        patch('pki.services.owner_credential.EstDeviceCsrSignProcessor') as signer,
        patch('pki.services.owner_credential.EstClient') as client,
    ):
        builder.return_value.get_csr.return_value = csr
        signer.return_value.get_signed_csr.return_value = csr
        client.return_value.simple_enroll.return_value = certificate
        enroll_owner_credential_est(
            context, owner, pending, logger=logging.getLogger(__name__), domain_credential=domain
        )

    pending.refresh_from_db()
    credential.refresh_from_db()
    assert pending.credential_id == credential.pk
    assert credential.get_private_key_serializer().as_pkcs8_pem() == private_pem
    assert credential.get_certificate().public_bytes(serialization.Encoding.DER) == certificate.public_bytes(
        serialization.Encoding.DER
    )
    assert PrimaryCredentialCertificate.objects.filter(
        credential=credential, certificate=credential.certificate, is_primary=True
    ).exists()
    assert pending.common_name == 'issued-owner'
    assert pending.issued_using_cert_profile == ('selected-profile' if domain else 'original-profile')
    references = IDevIDReferenceModel.objects.filter(dev_owner_id=owner)
    if domain:
        assert not references.exists()
    else:
        reference = references.get(idevid_ref='dev-owner:device-one')
        assert reference.dev_owner_id_certificate_id == credential.certificate_id


def test_est_failure_keeps_the_pending_record_unissued(enrollment):
    domain, owner, pending, context = enrollment
    original_key = pending.credential.get_private_key_serializer().as_pkcs8_pem()
    with (
        patch('pki.services.owner_credential.ProfileAwareCsrBuilder'),
        patch('pki.services.owner_credential.EstDeviceCsrSignProcessor'),
        patch('pki.services.owner_credential.EstClient') as client,
    ):
        client.return_value.simple_enroll.side_effect = EstClientError('remote failure')
        with pytest.raises(EstClientError, match='remote failure'):
            enroll_owner_credential_est(
                context, owner, pending, logger=logging.getLogger(__name__), domain_credential=domain
            )
    pending.refresh_from_db()
    assert pending.credential.certificate_id is None
    assert pending.credential.get_private_key_serializer().as_pkcs8_pem() == original_key
    assert pending.issued_using_cert_profile == 'original-profile'
    assert not IDevIDReferenceModel.objects.filter(dev_owner_id=owner).exists()
