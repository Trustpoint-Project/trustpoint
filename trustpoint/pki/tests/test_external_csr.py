"""Tests for shared external CSR operations with actual managed keys."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.core.management import call_command

from pki.models import CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.services.key_generation import generate_pending_credential
from request.operation_processor.csr_build import ProfileAwareCsrBuilder
from request.request_context import CmpCertificateRequestContext

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize('key_type', ['ECC-SECP256R1', 'RSA-2048'])
def test_actual_managed_key_csr(key_type):
    call_command('create_default_cert_profiles')
    credential = generate_pending_credential(
        alias=f'external-csr/{key_type}', key_type=key_type,
        credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
    )
    profile = CertificateProfileModel.objects.get(unique_name='tls_server')
    context = CmpCertificateRequestContext(
        operation='certification', protocol='cmp', domain=None,
        cert_profile_str=profile.unique_name, certificate_profile_model=profile,
    )
    context.owner_credential = credential
    context.request_data = {
        'subj': {'common_name': 'server.example', 'organization_name': 'Example', 'country_name': 'DE'},
        'ext': {'subject_alternative_name': {'dns_names': ['server.example']}},
        'validity': {'days': 10},
    }
    builder = ProfileAwareCsrBuilder()
    builder.process_operation(context)
    csr = builder.get_csr()
    assert csr.is_signature_valid
    assert csr.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == (
        credential.get_private_key().public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    assert csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == 'server.example'