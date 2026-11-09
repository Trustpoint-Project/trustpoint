# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the IssuedCredential model."""

from typing import Any

import pytest
from pki.models import CredentialModel, RevokedCertificateModel

from pki.models import IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models import CertificateModel
from pki.models.credential import PrimaryCredentialCertificate
from pki.util.x509 import CertificateGenerator


@pytest.fixture
def profile() -> CertificateProfileModel:
    return CertificateProfileModel.objects.get_or_create(
        unique_name='tls_client', defaults={'display_name': 'TLS Client', 'profile_json': {}}
    )[0]


@pytest.mark.django_db
def test_revoked_historical_certificate_cannot_inherit_replacement_validity(
    credential_instance, device_instance, profile
):
    credential = credential_instance['credential']
    old = credential.certificate
    old_certificate = old.get_certificate_serializer().as_crypto()
    replacement, _ = CertificateGenerator.create_ee(
        issuer_private_key=credential_instance['priv_key'],
        issuer_name=credential_instance['cert'].subject,
        subject_name='Replacement',
        private_key=credential.get_private_key(),
    )
    new = CertificateModel.save_certificate(replacement)
    PrimaryCredentialCertificate.objects.create(credential=credential, certificate=new)
    credential.certificate = new
    credential.save()
    device = device_instance['device']
    issued = IssuedCredentialModel.objects.create(
        common_name='Historical authentication',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        certificate_profile=profile,
        credential=credential,
        device=device,
        domain=device.domain,
    )
    RevokedCertificateModel.objects.create(certificate=old)
    assert issued.is_valid_domain_credential()[0]
    assert IssuedCredentialModel.get_credential_for_certificate(replacement) == issued
    with pytest.raises(IssuedCredentialModel.DoesNotExist, match='not active'):
        IssuedCredentialModel.get_credential_for_certificate(old_certificate)


@pytest.mark.django_db
def test_issued_credential_creation(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """Test the creation of an IssuedCredentialModel linked to a valid credential."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Test Issued Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
        credential=credential,
        device=device,
        domain=device.domain,
    )

    assert issued_credential.pk is not None, 'The issued credential should be saved to the database.'
    assert issued_credential.credential == credential, 'The issued credential should refer to the correct credential.'
    assert issued_credential.device == device, 'The issued credential should be linked to the correct device.'
    assert issued_credential.domain == device.domain, 'The issued credential should be linked to the correct domain.'
    assert issued_credential.issued_credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    assert issued_credential.certificate_profile == profile
    assert issued_credential.common_name == 'Test Issued Credential', 'The common name should match the input.'


@pytest.mark.django_db
def test_is_valid_domain_credential(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """Test the validity of an IssuedCredentialModel instance as a domain credential."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Valid Domain Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        certificate_profile=profile,
        credential=credential,
        device=device,
        domain=device.domain,
    )

    is_valid, reason = issued_credential.is_valid_domain_credential()
    assert is_valid is True, f'The domain credential should be valid. Reason: {reason}'


@pytest.mark.django_db
def test_revoke_issued_credential(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """Test the revocation of all certificates associated with an IssuedCredentialModel."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Credential To Revoke',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
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
def test_get_credential_for_certificate(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """Test retrieving the IssuedCredentialModel for a given certificate."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Retrieved Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
        credential=credential,
        device=device,
        domain=device.domain,
    )

    cert = credential.certificate.get_certificate_serializer().as_crypto()
    retrieved_credential = IssuedCredentialModel.get_credential_for_certificate(cert)
    assert retrieved_credential == issued_credential, 'The retrieved credential should match the created credential.'


@pytest.mark.django_db
def test_pre_delete_issued_credential(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """Test the `pre_delete` method for IssuedCredentialModel."""
    device = device_instance['device']
    credential = credential_instance['credential']

    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Credential To Delete',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
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
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """The string form names the credential and a device is mandatory."""
    from django.core.exceptions import ValidationError

    issued_credential = IssuedCredentialModel(
        common_name='Named Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
        credential=credential_instance['credential'],
        domain=device_instance['device'].domain,
    )

    assert str(issued_credential) == 'IssuedCredentialModel(common_name=Named Credential)'
    with pytest.raises(ValidationError, match='device'):
        issued_credential.clean()


@pytest.mark.django_db
def test_application_credential_is_not_a_domain_credential(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """Application credentials cannot be used to enrol further credentials."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Application Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )

    is_valid, reason = issued_credential.is_valid_domain_credential()

    assert is_valid is False
    assert 'DOMAIN_CREDENTIAL' in reason


@pytest.mark.django_db
def test_revocation_is_skipped_without_a_domain(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """A credential without a domain has no issuing CA and is not revoked."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Domainless Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )
    issued_credential.domain = None

    issued_credential.revoke()

    assert not RevokedCertificateModel.objects.filter(certificate=issued_credential.credential.certificate).exists()


@pytest.mark.django_db
def test_already_revoked_certificates_are_not_revoked_again(
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """Revoking twice does not create duplicate revocation entries."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Twice Revoked Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )
    issued_credential.revoke()

    issued_credential.revoke()

    assert RevokedCertificateModel.objects.filter(certificate=issued_credential.credential.certificate).count() == 1


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
    credential_instance: dict[str, Any], device_instance: dict[str, Any], profile: CertificateProfileModel
) -> None:
    """A known serial number resolves to its issued credential."""
    device = device_instance['device']
    issued_credential = IssuedCredentialModel.objects.create(
        common_name='Serial Lookup Credential',
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
        credential=credential_instance['credential'],
        device=device,
        domain=device.domain,
    )
    serial = issued_credential.credential.certificate.serial_number

    found = IssuedCredentialModel.get_credential_for_serial_number(device.domain, device, serial)

    assert found == issued_credential


def test_profile_reference_controls_label_and_prevents_deletion(credential_instance, device_instance, profile) -> None:
    from django.db.models.deletion import ProtectedError
    from pki.serializer.certificate import CertificateIssuedCredentialSerializer

    issued = IssuedCredentialModel.objects.create(
        common_name='profile-reference',
        credential=credential_instance['credential'],
        device=device_instance['device'],
        domain=device_instance['domain'],
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        certificate_profile=profile,
    )
    profile.display_name = 'Renamed profile'
    profile.save(update_fields=['display_name'])
    issued.refresh_from_db()
    assert issued.issued_using_cert_profile == 'Renamed profile'
    assert CertificateIssuedCredentialSerializer(issued).data['issued_using_cert_profile'] == 'Renamed profile'
    assert 'issued_using_cert_profile' not in {field.name for field in issued._meta.fields}
    with pytest.raises(ProtectedError):
        profile.delete()
    profile.display_name = ''
    profile.save(update_fields=['display_name'])
    issued.refresh_from_db()
    assert issued.issued_using_cert_profile == profile.unique_name
