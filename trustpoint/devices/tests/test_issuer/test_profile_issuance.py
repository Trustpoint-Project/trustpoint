# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Certificate roles use profiles with the shared credential issuance processors."""

import copy
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.utils import timezone

from onboarding.models import OnboardingStatus
from pki.models import IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.tests.credential_helpers import issue_test_credential
from pki.util.keys import KeyGenerator


@pytest.mark.parametrize('external_key', [False, True])
@pytest.mark.parametrize(
    ('profile_name', 'expected_days', 'expected_ekus'),
    [
        ('tls_client', 10, {x509.ExtendedKeyUsageOID.CLIENT_AUTH}),
        ('tls_server', 10, {x509.ExtendedKeyUsageOID.SERVER_AUTH}),
        ('opc_ua', 365, {x509.ExtendedKeyUsageOID.CLIENT_AUTH, x509.ExtendedKeyUsageOID.SERVER_AUTH}),
        ('domain_credential', 30, None),
    ],
)
def test_profile_issued_certificate_policy_and_storage(
    device_instance: dict[str, Any],
    *,
    profile_name: str,
    expected_days: int,
    expected_ekus: set[x509.ObjectIdentifier] | None,
    external_key: bool,
) -> None:
    """The profile governs certificate contents for generated keys and externally supplied keys."""
    device = device_instance['device']
    now = timezone.now()
    key = KeyGenerator.generate_private_key(domain=device.domain) if external_key else None
    credential = issue_test_credential(
        device,
        profile_name,
        common_name='Profile certificate',
        public_key=key.public_key_serializer.as_crypto() if key else None,
    )
    certificate = credential.credential.get_certificate()
    assert credential.device == device
    assert credential.domain == device.domain
    assert credential.common_name == 'Profile certificate'
    profile = CertificateProfileModel.objects.get(unique_name=profile_name)
    assert credential.issued_using_cert_profile == profile.display_name
    expected_type = (
        IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
        if profile_name == 'domain_credential'
        else IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    )
    assert credential.issued_credential_type == expected_type
    assert abs(certificate.not_valid_after_utc - now - timedelta(days=expected_days)) < timedelta(minutes=1)
    assert certificate.subject.get_attributes_for_oid(x509.NameOID.USER_ID)[0].value == str(device.pk)
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    if expected_ekus is not None:
        assert set(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == expected_ekus
    assert credential.credential.get_certificate_chain()
    if key:
        assert certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == key.public_key_serializer.as_crypto().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert not credential.credential.private_key
    else:
        assert credential.credential.get_private_key() is not None


def test_profile_san_and_extension_criticality(device_instance: dict[str, Any]) -> None:
    """A configured OPC UA profile supplies SAN policy and extension criticality."""
    device = device_instance['device']
    uri = 'urn:example:opcua:server'
    san = x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri), x509.DNSName('opc.example.test')])
    issued = issue_test_credential(device, 'opc_ua', extensions=[(san, False)])
    cert = issued.credential.get_certificate()
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).critical
    actual = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert actual.value.get_values_for_type(x509.UniformResourceIdentifier) == [uri]
    assert actual.value.get_values_for_type(x509.DNSName) == ['opc.example.test']


def test_changed_profile_changes_certificate_policy(device_instance: dict[str, Any]) -> None:
    """Updating profile validity and criticality takes effect without a role-specific issuer."""
    device = device_instance['device']
    definition = json.loads(
        (Path(__file__).resolve().parents[3] / 'pki/default_certificate_profiles/tls_client.json').read_text()
    )
    definition = copy.deepcopy(definition)
    definition['validity'] = {'days': 7}
    definition['ext']['basic_constraints']['critical'] = True
    now = timezone.now()
    issued = issue_test_credential(device, 'tls_client', profile_data=definition)
    cert = issued.credential.get_certificate()
    assert abs(cert.not_valid_after_utc - now - timedelta(days=7)) < timedelta(minutes=1)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).critical


@pytest.mark.parametrize('external_key', [False, True])
def test_domain_issuance_defers_onboarding_completion(
    device_instance_onboarding: dict[str, Any],
    *,
    external_key: bool,
) -> None:
    """Creating a domain certificate alone does not retire secrets before protocol completion."""
    device = device_instance_onboarding['device']
    key = KeyGenerator.generate_private_key(domain=device.domain) if external_key else None
    issued = issue_test_credential(
        device,
        'domain_credential',
        public_key=key.public_key_serializer.as_crypto() if key else None,
    )
    assert issued.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
    device.onboarding_config.refresh_from_db()
    assert device.onboarding_config.onboarding_status == OnboardingStatus.PENDING
