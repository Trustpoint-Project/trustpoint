"""Test suite for validating the TLS Client Credential functionality."""

from typing import Any

import pytest
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import SubjectAlternativeName, UniformResourceIdentifier

from devices.issuer import LocalTlsClientCredentialIssuer
from devices.models import IssuedCredentialModel


@pytest.mark.django_db
def test_issue_tls_client_credential(device_instance: dict[str, Any]) -> None:
    """Test that issuing a TLS client credential."""
    device = device_instance['device']

    issuer = LocalTlsClientCredentialIssuer(device=device, domain=device.domain)

    common_name = 'Test TLS Client Credential'
    validity_days = 365

    issued_credential = issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity_days)

    assert isinstance(issued_credential, IssuedCredentialModel), (
        'The returned object should be an IssuedCredentialModel'
    )
    assert issued_credential.common_name == common_name, 'The common name of the issued credential should match'
    assert issued_credential.device == device, 'The issued credential should belong to the correct device'
    assert issued_credential.domain == device.domain, 'The issued credential should belong to the correct domain'
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT

    db_credential = IssuedCredentialModel.objects.get(pk=issued_credential.pk)
    assert db_credential == issued_credential, 'The credential should be saved correctly in the database'


@pytest.mark.django_db
def test_issue_tls_client_certificate(
    device_instance: dict[str, Any], ec_private_key: ec.EllipticCurvePrivateKey
) -> None:
    """Test issuing a TLS client certificate using the `issue_tls_client_certificate` method."""
    device = device_instance['device']

    issuer = LocalTlsClientCredentialIssuer(device=device, domain=device.domain)

    common_name = 'Test TLS Client Certificate'
    validity_days = 365

    public_key = ec_private_key.public_key()

    issued_credential = issuer.issue_tls_client_certificate(
        common_name=common_name, validity_days=validity_days, public_key=public_key
    )

    assert isinstance(issued_credential, IssuedCredentialModel), (
        'The returned object should be an IssuedCredentialModel.'
    )
    assert issued_credential.common_name == common_name, 'The common name of the issued credential should match.'
    assert issued_credential.device == device, 'The issued credential should belong to the correct device.'
    assert issued_credential.domain == device.domain, 'The issued credential should belong to the correct domain.'
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT

    certificate = issued_credential.credential.get_certificate()
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == common_name, (
        "The certificate's common name should match the issued common name."
    )

    san_extension = certificate.extensions.get_extension_for_class(SubjectAlternativeName).value
    san_uris = san_extension.get_values_for_type(UniformResourceIdentifier)
    expected_san_uri = f'{common_name.replace(" ", "")}.alt'

    assert expected_san_uri in san_uris, (
        f'The SAN should include the expected URI value. Expected: {expected_san_uri}, Found: {san_uris}'
    )
