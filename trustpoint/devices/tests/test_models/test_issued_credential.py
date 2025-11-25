"""Tests for the IssuedCredential model."""

from typing import Any

import pytest
from pki.models import CredentialModel, RevokedCertificateModel

from devices.models import IssuedCredentialModel


@pytest.mark.django_db
def test_issued_credential_creation(credential_instance: dict[str, Any], device_instance: dict[str, Any]) -> None:
    """Test the creation of an IssuedCredentialModel linked to a valid credential."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Test Issued Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential,
        device=device,
        domain=device.domain,
    )

    assert issued_credential.pk is not None, 'The issued credential should be saved to the database.'
    assert issued_credential.credential == credential, 'The issued credential should refer to the correct credential.'
    assert issued_credential.device == device, 'The issued credential should be linked to the correct device.'
    assert issued_credential.domain == device.domain, 'The issued credential should be linked to the correct domain.'
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.issued_using_cert_profile == 'TLS Client'
    assert issued_credential.common_name == 'Test Issued Credential', 'The common name should match the input.'


@pytest.mark.django_db
def test_is_valid_domain_credential(credential_instance: dict[str, Any], device_instance: dict[str, Any]) -> None:
    """Test the validity of an IssuedCredentialModel instance as a domain credential."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Valid Domain Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        issued_using_cert_profile='Trustpoint Domain Credential',
        credential=credential,
        device=device,
        domain=device.domain,
    )

    is_valid, reason = issued_credential.is_valid_domain_credential()
    assert is_valid is True, f'The domain credential should be valid. Reason: {reason}'


@pytest.mark.django_db
def test_revoke_issued_credential(credential_instance: dict[str, Any], device_instance: dict[str, Any]) -> None:
    """Test the revocation of all certificates associated with an IssuedCredentialModel."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Credential To Revoke',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential,
        device=device,
        domain=device.domain,
    )

    assert not hasattr(issued_credential.credential.certificate, 'revoked_certificate'), (
        'No certificates should be revoked initially.'
    )

    issued_credential.revoke()

    # Verify the associated certificate is revoked
    revoked_certificate = RevokedCertificateModel.objects.filter(
        certificate=issued_credential.credential.certificate
    ).first()
    assert revoked_certificate is not None, 'The certificate should be marked as revoked.'
    assert revoked_certificate.revocation_reason == RevokedCertificateModel.ReasonCode.CESSATION, (
        "The revocation reason should be 'cessationOfOperation'."
    )


@pytest.mark.django_db
def test_get_credential_for_certificate(credential_instance: dict[str, Any], device_instance: dict[str, Any]) -> None:
    """Test retrieving the IssuedCredentialModel for a given certificate."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Retrieved Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential,
        device=device,
        domain=device.domain,
    )

    cert = credential.certificate.get_certificate_serializer().as_crypto()
    retrieved_credential = IssuedCredentialModel.get_credential_for_certificate(cert)
    assert retrieved_credential == issued_credential, 'The retrieved credential should match the created credential.'


@pytest.mark.django_db
def test_pre_delete_issued_credential(credential_instance: dict[str, Any], device_instance: dict[str, Any]) -> None:
    """Test the `pre_delete` method for IssuedCredentialModel."""
    device = device_instance['device']
    credential = credential_instance['credential']
    credential.save()

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Credential To Delete',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential,
        device=device,
        domain=device.domain,
    )

    issued_credential.pre_delete()

    assert not IssuedCredentialModel.objects.filter(pk=issued_credential.pk).exists(), (
        'The issued credential should be deleted after `pre_delete` is called.'
    )

    assert not CredentialModel.objects.filter(pk=credential.pk).exists(), (
        'The credential instance should be deleted after `pre_delete` is called.'
    )
