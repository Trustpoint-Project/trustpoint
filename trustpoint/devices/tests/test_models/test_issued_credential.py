import pytest
from devices.models import IssuedCredentialModel
from pki.models import RevokedCertificateModel, CredentialModel


@pytest.mark.django_db
def test_issued_credential_creation(credential_instance, test_device):
    """
    Test the creation of an IssuedCredentialModel linked to a valid credential.
    """
    issued_credential = IssuedCredentialModel.objects.create(
        common_name="Test Issued Credential",
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT,
        credential=credential_instance,
        device=test_device,
        domain=test_device.domain,
    )

    assert issued_credential.pk is not None, "The issued credential should be saved to the database."
    assert issued_credential.credential == credential_instance, "The issued credential should refer to the correct credential."
    assert issued_credential.device == test_device, "The issued credential should be linked to the correct device."
    assert issued_credential.domain == test_device.domain, "The issued credential should be linked to the correct domain."
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_credential_purpose == IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT
    assert issued_credential.common_name == "Test Issued Credential", "The common name should match the input."

@pytest.mark.django_db
def test_is_valid_domain_credential(credential_instance, test_device):
    """
    Test the validity of an IssuedCredentialModel instance as a domain credential.
    """
    issued_credential = IssuedCredentialModel.objects.create(
        common_name="Valid Domain Credential",
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.DOMAIN_CREDENTIAL,
        credential=credential_instance,
        device=test_device,
        domain=test_device.domain,
    )

    is_valid, reason = issued_credential.is_valid_domain_credential()
    assert is_valid is True, f"The domain credential should be valid. Reason: {reason}"

@pytest.mark.django_db
def test_revoke_issued_credential(credential_instance, test_device):
    """
    Test the revocation of all certificates associated with an IssuedCredentialModel.
    """
    issued_credential = IssuedCredentialModel.objects.create(
        common_name="Credential To Revoke",
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT,
        credential=credential_instance,
        device=test_device,
        domain=test_device.domain,
    )

    assert not hasattr(issued_credential.credential.certificate, 'revoked_certificate'), (
        "No certificates should be revoked initially."
    )

    issued_credential.revoke()

    # Verify the associated certificate is revoked
    revoked_certificate = RevokedCertificateModel.objects.filter(
        certificate=issued_credential.credential.certificate
    ).first()
    assert revoked_certificate is not None, "The certificate should be marked as revoked."
    assert revoked_certificate.revocation_reason == RevokedCertificateModel.ReasonCode.CESSATION, (
        "The revocation reason should be 'cessationOfOperation'."
    )

@pytest.mark.django_db
def test_get_credential_for_certificate(credential_instance, test_device):
    """
    Test retrieving the IssuedCredentialModel for a given certificate.
    """
    issued_credential = IssuedCredentialModel.objects.create(
        common_name="Retrieved Credential",
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT,
        credential=credential_instance,
        device=test_device,
        domain=test_device.domain,
    )

    cert = credential_instance.certificate.get_certificate_serializer().as_crypto()
    retrieved_credential = IssuedCredentialModel.get_credential_for_certificate(cert)
    assert retrieved_credential == issued_credential, "The retrieved credential should match the created credential."

@pytest.mark.django_db
def test_pre_delete_issued_credential(credential_instance, test_device):
    """
    Test the `pre_delete` method for IssuedCredentialModel.
    """
    credential_instance.save()

    issued_credential = IssuedCredentialModel.objects.create(
        common_name="Credential To Delete",
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_credential_purpose=IssuedCredentialModel.IssuedCredentialPurpose.TLS_CLIENT,
        credential=credential_instance,
        device=test_device,
        domain=test_device.domain,
    )

    issued_credential.pre_delete()

    assert not IssuedCredentialModel.objects.filter(pk=issued_credential.pk).exists(), (
        "The issued credential should be deleted after `pre_delete` is called."
    )

    assert not CredentialModel.objects.filter(pk=credential_instance.pk).exists(), (
        "The credential instance should be deleted after `pre_delete` is called."
    )


