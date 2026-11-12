# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""TLS server credential enrollment via EST and local Issuing CA."""

import datetime as dt
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.core.management import call_command

from crypto.models import CryptoManagedKeyModel
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import CaModel, CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import TruststoreModel
from pki.services.key_generation import generate_pending_credential
from pki.services.tls_server_issuance import (
    finalize_tls_server_enrollment,
    issue_tls_server_local,
    issue_tls_server_remote,
)
from pki.forms.truststores import TruststoreAddForm
from pki.tests.managed_ca_helpers import create_managed_root_ca

pytestmark = pytest.mark.django_db

CONTENT = {
    'common_name': 'server.example',
    'organization_name': 'Example',
    'country_name': 'DE',
    'dns_names': 'server.example',
    'days': 10,
}


@pytest.fixture(autouse=True)
def _profiles() -> None:
    call_command('create_default_cert_profiles')


def _pending_credential() -> CredentialModel:
    return generate_pending_credential(
        alias=f'tls-issuance/{uuid4().hex}',
        key_type='ECC-SECP256R1',
        credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
    )


def _local_ca(unique_name: str) -> tuple[CaModel, x509.Certificate]:
    ca_cert, ca_key = create_managed_root_ca(unique_name)
    credential = CredentialModel.save_managed_key_credential(
        certificate=ca_cert,
        certificate_chain=[],
        credential_type=CredentialModel.CredentialTypeChoice.ISSUING_CA,
        managed_key=CryptoManagedKeyModel.objects.get(pk=ca_key.managed_key_ref.id),
    )
    ca = CaModel(unique_name=unique_name, credential=credential, ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT)
    ca.save()
    ca.chain_truststore = CaModel._create_chain_truststore(ca)  # noqa: SLF001
    ca.save(update_fields=['chain_truststore'])
    return ca, ca_cert


def test_issue_tls_server_local_signs_with_local_ca() -> None:
    """A local Issuing CA signs the TLS server credential and the chain is stored."""
    ca, ca_cert = _local_ca('Test Root CA')
    profile = CertificateProfileModel.objects.get(unique_name='tls_server')
    pending = _pending_credential()

    issue_tls_server_local(pending, profile, CONTENT, ca)

    pending.refresh_from_db()
    cert = pending.get_certificate()
    cert.verify_directly_issued_by(ca_cert)
    assert cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == (
        pending.get_private_key().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    assert [c.subject for c in pending.get_certificate_chain()] == [ca_cert.subject]


def test_issue_tls_server_remote_uses_external_est_configuration() -> None:
    """An EST RA management CA forwards the TLS request using its stored enrollment settings."""
    truststore = TruststoreModel.objects.create(
        unique_name='remote-est-trust',
        intended_usage=TruststoreModel.IntendedUsage.TLS,
    )
    config = NoOnboardingConfigModel.objects.create(
        pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
        est_password='secret',
        trust_store=truststore,
    )
    ca = CaModel.objects.create(
        unique_name='External EST Management CA',
        ca_type=CaModel.CaTypeChoice.REMOTE_EST_RA,
        ca_role=CaModel.CaRole.MANAGEMENT,
        remote_host='ca.example',
        remote_port=8443,
        remote_path='/.well-known/est/simpleenroll',
        est_username='user',
        no_onboarding_config=config,
    )
    profile = CertificateProfileModel.objects.get(unique_name='tls_server')
    pending = _pending_credential()

    with (
        patch('pki.services.tls_server_issuance.enroll_est') as enroll,
        patch('pki.services.tls_server_issuance.finalize_tls_server_enrollment') as finalize,
    ):
        enroll.return_value = (Mock(), [])
        result = issue_tls_server_remote(pending, profile, CONTENT, ca)

    context = enroll.call_args.args[0]
    assert context.est_server_host == 'ca.example'
    assert context.est_username == 'user'
    assert context.est_server_truststore == truststore
    finalize.assert_called_once()
    assert result is finalize.return_value


def test_finalize_tls_server_enrollment_attaches_certificate() -> None:
    """An EST-issued certificate that chains to the truststore is attached to the pending key."""
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'External CA')])
    now = dt.datetime.now(dt.UTC)
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    truststore = TruststoreAddForm.save_trust_store('est-tls', TruststoreModel.IntendedUsage.TLS, [issuer_cert])

    pending = _pending_credential()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'server.example')]))
        .issuer_name(issuer_name)
        .public_key(pending.get_private_key().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('server.example')]), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pending.get_private_key().public_key()), critical=False
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )

    finalize_tls_server_enrollment(pending, leaf, [issuer_cert], truststore)

    pending.refresh_from_db()
    cert = pending.get_certificate()
    assert cert.issuer == issuer_name
    assert [c.subject for c in pending.get_certificate_chain()] == [issuer_name]


def test_finalize_tls_server_enrollment_rejects_untrusted_certificate() -> None:
    """A certificate that does not chain to the truststore is rejected before persistence."""
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Trusted CA')])
    now = dt.datetime.now(dt.UTC)
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    truststore = TruststoreAddForm.save_trust_store('est-tls-2', TruststoreModel.IntendedUsage.TLS, [issuer_cert])

    pending = _pending_credential()
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Rogue CA')])
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_name)
        .issuer_name(rogue_name)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(rogue_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'server.example')]))
        .issuer_name(rogue_name)
        .public_key(pending.get_private_key().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=10))
        .sign(rogue_key, hashes.SHA256())
    )

    with pytest.raises(ValueError, match='does not chain'):
        finalize_tls_server_enrollment(pending, leaf, [rogue_cert], truststore)

    pending.refresh_from_db()
    assert pending.certificate_id is None
