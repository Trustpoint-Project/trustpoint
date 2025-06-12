"""Test suite for validating the OPC UA Client Credential functionality."""
from typing import Any

import pytest
from cryptography.x509 import SubjectAlternativeName, UniformResourceIdentifier

from devices.issuer import OpcUaClientCredentialIssuer
from devices.models import IssuedCredentialModel


@pytest.mark.django_db
def test_issue_opcua_client_credential(device_instance: dict[str, Any]) -> None:
    """Test that issuing an OPC UA client credential works without mocks."""
    device = device_instance['device']

    issuer = OpcUaClientCredentialIssuer(device=device, domain=device.domain)

    # Input parameters
    common_name = 'Test OPC UA Client Credential'
    application_uri = 'urn:example:opcua:client'
    validity_days = 365

    issued_credential = issuer.issue_opcua_client_credential(
        common_name=common_name,
        application_uri=application_uri,
        validity_days=validity_days,
    )

    assert isinstance(issued_credential, IssuedCredentialModel), \
        'The returned object should be an IssuedCredentialModel'
    assert issued_credential.common_name == common_name, 'The common name should match the input'
    assert issued_credential.device == device, 'The issued credential should belong to the correct device'
    assert issued_credential.domain == device.domain, 'The issued credential should belong to the correct domain'
    assert (issued_credential.issued_credential_type ==
            IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL), \
        'The issued_credential_type should be APPLICATION_CREDENTIAL'
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.OPCUA_CLIENT, \
        'The issued_credential_purpose should be OPCUA_CLIENT'

    db_credential = IssuedCredentialModel.objects.get(pk=issued_credential.pk)
    assert db_credential == issued_credential, 'The credential should be saved correctly in the database'

    certificate = issued_credential.credential.get_certificate()
    san_extension = certificate.extensions.get_extension_for_class(SubjectAlternativeName).value

    san_uris = san_extension.get_values_for_type(UniformResourceIdentifier)
    assert application_uri in san_uris, f'The application URI {application_uri} should be present in the SAN'

    cert_chain = issued_credential.credential.get_certificate_chain()
    assert isinstance(cert_chain, list), 'The certificate chain should be a list'
    assert len(cert_chain) > 0, 'The certificate chain should not be empty'
    assert all(cert is not None for cert in cert_chain), 'All certificates in the chain should be valid'
