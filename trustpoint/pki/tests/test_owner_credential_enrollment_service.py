# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Remote enrollment keeps the pending key and applies only the selected role's updates."""

import datetime
import logging
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
        certificate_profile_model=CertificateProfileModel.objects.create(
            unique_name='selected-profile', profile_json={'type': 'cert_profile'}
        ),
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
        patch('pki.services.est_enrollment.ProfileAwareCsrBuilder') as builder,
        patch('pki.services.est_enrollment.EstDeviceCsrSignProcessor') as signer,
        patch('pki.services.est_enrollment.EstClient') as client,
    ):
        builder.return_value.get_csr.return_value = csr
        signer.return_value.get_signed_csr.return_value = csr
        client.return_value.simple_enroll.return_value = (certificate, [])
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
    assert pending.certificate_profile == context.certificate_profile_model
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
        patch('pki.services.est_enrollment.ProfileAwareCsrBuilder'),
        patch('pki.services.est_enrollment.EstDeviceCsrSignProcessor'),
        patch('pki.services.est_enrollment.EstClient') as client,
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


@pytest.mark.parametrize('mismatch', ['key', 'role'])
def test_est_result_binding_fails_before_certificate_persistence(enrollment, mismatch):
    domain, owner, pending, context = enrollment
    key = pending.credential.get_private_key()
    result_key = ec.generate_private_key(ec.SECP256R1()) if mismatch == 'key' else key
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'owner')])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(result_key.public_key())
        .serial_number(43)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=mismatch == 'role', path_length=None), critical=True)
        .sign(result_key, hashes.SHA256())
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    with (
        patch('pki.services.est_enrollment.ProfileAwareCsrBuilder') as builder,
        patch('pki.services.est_enrollment.EstDeviceCsrSignProcessor') as signer,
        patch('pki.services.est_enrollment.EstClient') as client,
        patch('pki.services.owner_credential.CertificateModel.save_certificate') as save,
    ):
        builder.return_value.get_csr.return_value = csr
        signer.return_value.get_signed_csr.return_value = csr
        client.return_value.simple_enroll.return_value = (certificate, [])
        with pytest.raises(ValueError, match='does not match'):
            enroll_owner_credential_est(
                context, owner, pending, logger=logging.getLogger(__name__), domain_credential=domain
            )
        save.assert_not_called()
    pending.credential.refresh_from_db()
    assert pending.credential.certificate_id is None


def test_owner_enrollment_requires_profile_before_sending_request(enrollment):
    domain, owner, pending, context = enrollment
    context.certificate_profile_model = None
    with patch('pki.services.est_enrollment.EstClient') as client:
        with pytest.raises(ValueError, match='certificate profile is required'):
            enroll_owner_credential_est(
                context, owner, pending, logger=logging.getLogger(__name__), domain_credential=domain
            )
        client.assert_not_called()
    pending.refresh_from_db()
    assert pending.certificate_profile.unique_name == 'original-profile'
