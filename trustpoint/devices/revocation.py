"""Module to handle revocation logic for devices and device credentials."""

from __future__ import annotations

from pki.models.certificate import RevokedCertificateModel

from devices.models import IssuedCredentialModel


class DeviceCredentialRevocation:
    """Class to handle revocation logic for devices and device credentials."""

    @staticmethod
    def revoke_certificate(issued_credential_id: int, reason: str) -> tuple[bool, str]:
        """Revokes a certificate given an ID of an IssuedCredentialModel instance"""
        try:
            issued_credential = IssuedCredentialModel.objects.get(id=issued_credential_id)
        except IssuedCredentialModel.DoesNotExist:
            return False, 'The credential to revoke does not exist.'

        primary_cert = issued_credential.credential.certificate

        if not primary_cert:
            return False, 'The associated certificate to revoke was not found.'

        if hasattr(primary_cert, 'revoked_certificate'):
            return False, 'The certificate is already revoked.'

        RevokedCertificateModel.objects.create(
            certificate=primary_cert, revocation_reason=reason, ca=issued_credential.domain.issuing_ca
        )
        return True, 'Certificate successfully revoked.'
