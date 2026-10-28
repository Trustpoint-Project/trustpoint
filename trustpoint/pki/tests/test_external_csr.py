# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for shared external CSR operations with actual managed keys."""

from copy import deepcopy

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.core.management import call_command

from pki.models import CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.services.external_csr import build_external_csr
from pki.services.key_generation import generate_pending_credential

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize('key_type', ['ECC-SECP256R1', 'RSA-2048'])
def test_actual_managed_key_csr(key_type: str) -> None:
    """Build an external CSR with the actual managed key and issuer-owned CRL policy."""
    call_command('create_default_cert_profiles')
    credential = generate_pending_credential(
        alias=f'external-csr/{key_type}', key_type=key_type,
        credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
    )
    profile = CertificateProfileModel.objects.get(unique_name='tls_server')
    original_profile = deepcopy(profile.profile)
    csr = build_external_csr(credential, profile, {
        'common_name': 'server.example',
        'organization_name': 'Example',
        'country_name': 'DE',
        'dns_names': 'server.example',
        'days': 10,
    })
    assert csr.is_signature_valid
    assert csr.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == (
        credential.get_private_key().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    assert csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'server.example'
    assert csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == ['server.example']
    with pytest.raises(x509.ExtensionNotFound):
        csr.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    assert profile.profile == original_profile
    profile.refresh_from_db()
    assert profile.profile == original_profile
