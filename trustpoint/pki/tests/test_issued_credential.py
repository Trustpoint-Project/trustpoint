# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the IssuedCredential model."""

from typing import Any

import pytest
from pki.models import CredentialModel, RevokedCertificateModel

from pki.models import IssuedCredentialModel


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


@pytest.mark.django_db
def test_str_and_clean_require_a_device(
    credential_instance: dict[str, Any], device_instance: dict[str, Any]
) -> None:
    """The string form names the credential and a device is mandatory."""
    from django.core.exceptions import ValidationError

    issued_credential = IssuedCredentialModel(
        common_name='Named Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential_instance['credential'],
        domain=device_instance['device'].domain,
    )

    assert str(issued_credential) == 'IssuedCredentialModel(common_name=Named Credential)'
    with pytest.raises(ValidationError, match='device'):
        issued_credential.clean()


@pytest.mark.django_db
def test_application_credential_is_not_a_domain_credential(
    credential_instance: dict[str, Any], device_instance: dict[str, Any]
) -> None:
    """Application credentials cannot be used to enrol further credentials."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Application Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )

    is_valid, reason = issued_credential.is_valid_domain_credential()

    assert is_valid is False
    assert 'DOMAIN_CREDENTIAL' in reason


@pytest.mark.django_db
def test_revocation_is_skipped_without_a_domain(
    credential_instance: dict[str, Any], device_instance: dict[str, Any]
) -> None:
    """A credential without a domain has no issuing CA and is not revoked."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Domainless Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )
    issued_credential.domain = None

    issued_credential.revoke()

    assert not RevokedCertificateModel.objects.filter(
        certificate=issued_credential.credential.certificate
    ).exists()


@pytest.mark.django_db
def test_already_revoked_certificates_are_not_revoked_again(
    credential_instance: dict[str, Any], device_instance: dict[str, Any]
) -> None:
    """Revoking twice does not create duplicate revocation entries."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Twice Revoked Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )
    issued_credential.revoke()

    issued_credential.revoke()

    assert RevokedCertificateModel.objects.filter(
        certificate=issued_credential.credential.certificate
    ).count() == 1


@pytest.mark.django_db
def test_unknown_certificate_lookup_raises(device_instance: dict[str, Any]) -> None:
    """Looking up an unknown certificate reports it as missing."""
    from pki.util.x509 import CertificateGenerator

    root, root_key = CertificateGenerator.create_root_ca('Lookup Root')
    unknown, _ = CertificateGenerator.create_ee(root_key, root.subject, 'unknown-cert')

    with pytest.raises(IssuedCredentialModel.DoesNotExist):
        IssuedCredentialModel.get_credential_for_certificate(unknown)


@pytest.mark.django_db
def test_unknown_serial_number_lookup_raises(device_instance: dict[str, Any]) -> None:
    """Looking up an unknown serial number reports it as missing."""
    device = device_instance['device']

    with pytest.raises(IssuedCredentialModel.DoesNotExist):
        IssuedCredentialModel.get_credential_for_serial_number(device.domain, device, 'DEADBEEF')


@pytest.mark.django_db
def test_serial_number_lookup_returns_matching_credential(
    credential_instance: dict[str, Any], device_instance: dict[str, Any]
) -> None:
    """A known serial number resolves to its issued credential."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Serial Lookup Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        issued_using_cert_profile='TLS Client',
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )
    serial = issued_credential.credential.certificate.serial_number

    found = IssuedCredentialModel.get_credential_for_serial_number(device.domain, device, serial)

    assert found == issued_credential
