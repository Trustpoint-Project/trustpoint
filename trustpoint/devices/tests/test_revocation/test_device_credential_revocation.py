"""Tests for the DeviceCredentialRevocation model."""

from typing import Any

import pytest
from pki.models import RevokedCertificateModel

from devices.revocation import DeviceCredentialRevocation


@pytest.mark.django_db
def test_revoke_certificate_success(tls_client_credential_instance: dict[str, Any]) -> None:
    """Test that a TLS client credential is successfully revoked for a valid issued credential."""
    issued_credential = tls_client_credential_instance['issued_credential']
    credential_id = issued_credential.pk

    success, message = DeviceCredentialRevocation.revoke_certificate(
        issued_credential_id=credential_id, reason='keyCompromise'
    )

    assert success is True, 'Revocation should be successful for a valid TLS client credential.'
    assert message == 'Certificate successfully revoked.', 'Successful revocation message should be returned.'

    revoked_cert = RevokedCertificateModel.objects.filter(certificate=issued_credential.credential.certificate).first()
    assert revoked_cert is not None, 'A RevokedCertificateModel instance should be created.'
    assert revoked_cert.revocation_reason == 'keyCompromise', 'The revocation reason should match the provided reason.'


@pytest.mark.django_db
def test_revoke_certificate_already_revoked(tls_client_credential_instance: dict[str, Any]) -> None:
    """Test that revoking a certificate that is already revoked returns the appropriate message."""
    issued_credential = tls_client_credential_instance['issued_credential']

    DeviceCredentialRevocation.revoke_certificate(issued_credential_id=issued_credential.pk, reason='keyCompromise')

    success, message = DeviceCredentialRevocation.revoke_certificate(
        issued_credential_id=issued_credential.pk, reason='keyCompromise'
    )

    assert success is False, 'Revocation should fail for an already revoked certificate.'
    assert message == 'The certificate is already revoked.', (
        'Message should indicate that the certificate is already revoked.'
    )


@pytest.mark.django_db
def test_revoke_certificate_invalid_id() -> None:
    """Test that revoking a certificate with an invalid `issued_credential_id` fails with the appropriate error."""
    invalid_credential_id = 999999  # Non-existent credential ID

    success, message = DeviceCredentialRevocation.revoke_certificate(
        issued_credential_id=invalid_credential_id, reason='keyCompromise'
    )

    assert success is False, 'Revocation should fail for a non-existent credential ID.'
    assert message == 'The credential to revoke does not exist.', (
        'Error message should indicate that the credential ID is invalid.'
    )
