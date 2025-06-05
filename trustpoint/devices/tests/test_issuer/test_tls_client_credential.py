import pytest
from cryptography.x509 import SubjectAlternativeName, UniformResourceIdentifier

from devices.models import DeviceModel, IssuedCredentialModel
from devices.issuer import LocalTlsClientCredentialIssuer
from trustpoint_core import oid


@pytest.mark.django_db
def test_issue_tls_client_credential(test_device):
    """Test that issuing a TLS client credential."""
    issuer = LocalTlsClientCredentialIssuer(device=test_device, domain=test_device.domain)

    common_name = "Test TLS Client Credential"
    validity_days = 365

    issued_credential = issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity_days)

    assert isinstance(issued_credential,
                      IssuedCredentialModel), "The returned object should be an IssuedCredentialModel"
    assert issued_credential.common_name == common_name, "The common name of the issued credential should match"
    assert issued_credential.device == test_device, "The issued credential should belong to the correct device"
    assert issued_credential.domain == test_device.domain, "The issued credential should belong to the correct domain"
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT

    db_credential = IssuedCredentialModel.objects.get(pk=issued_credential.pk)
    assert db_credential == issued_credential, "The credential should be saved correctly in the database"


@pytest.mark.django_db
def test_issue_tls_client_certificate(test_device, ec_private_key):
    """
    Test issuing a TLS client certificate using the `issue_tls_client_certificate` method.
    """
    issuer = LocalTlsClientCredentialIssuer(device=test_device, domain=test_device.domain)

    common_name = "Test TLS Client Certificate"
    validity_days = 365

    # Get the public key from the private key
    public_key = oid.PublicKey.from_cryptography_key(ec_private_key.public_key())

    # Issue the TLS client certificate without generating a private key
    issued_credential = issuer.issue_tls_client_certificate(
        common_name=common_name,
        validity_days=validity_days,
        public_key=public_key
    )

    # Assertions for the issued credential
    assert isinstance(issued_credential, IssuedCredentialModel), (
        "The returned object should be an IssuedCredentialModel."
    )
    assert issued_credential.common_name == common_name, "The common name of the issued credential should match."
    assert issued_credential.device == test_device, "The issued credential should belong to the correct device."
    assert issued_credential.domain == test_device.domain, "The issued credential should belong to the correct domain."
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT

    # Check the certificate details
    certificate = issued_credential.credential.get_certificate()
    assert certificate.subject.get_attributes_for_oid(certificate.oid.COMMON_NAME)[0].value == common_name, (
        "The certificate's common name should match the issued common name."
    )

    # Verify the Subject Alternative Name (SAN) extension
    san_extension = certificate.extensions.get_extension_for_class(SubjectAlternativeName).value
    san_uris = san_extension.get_values_for_type(UniformResourceIdentifier)
    assert f"{common_name.lower().replace(' ', '_')}.alt" in san_uris, (
        "The SAN should include the expected URI value."
    )

