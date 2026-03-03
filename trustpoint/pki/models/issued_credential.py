"""A model for issued credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta

from pki.models.certificate import CertificateModel, RevokedCertificateModel
from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    from cryptography import x509

    from devices.models import DeviceModel
    from pki.models.credential import CredentialModel  # noqa: F401
    from pki.models.domain import DomainModel


class IssuedCredentialModel(CustomDeleteActionModel):
    """Model for credentials and certificates issued to a device by the Trustpoint.

    Each instance must have a ``device`` FK set.  For credentials owned by a CA or
    an OwnerCredential, use :class:`RemoteIssuedCredentialModel` instead.
    """

    class IssuedCredentialType(models.IntegerChoices):
        """The type of the credential."""

        DOMAIN_CREDENTIAL = 0, _('Domain Credential')
        APPLICATION_CREDENTIAL = 1, _('Application Credential')

    id = models.AutoField(primary_key=True)

    common_name = models.CharField(verbose_name=_('Common Name'), max_length=255)
    issued_credential_type = models.IntegerField(choices=IssuedCredentialType, verbose_name=_('Credential Type'))
    issued_using_cert_profile = models.CharField(
        max_length=255, verbose_name=_('Issued using Certificate Profile'), default=''
    )
    credential = models.OneToOneField(
        'pki.CredentialModel',
        verbose_name=_('Credential'),
        on_delete=models.CASCADE,
        related_name='issued_credential',
        null=False,
        blank=False,
    )
    device = models.ForeignKey(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.PROTECT,
        related_name='issued_credentials',
        null=False,
        blank=False,
    )
    domain = models.ForeignKey(
        'pki.DomainModel',
        verbose_name=_('Domain'),
        on_delete=models.PROTECT,
        related_name='issued_credentials',
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Returns a human-readable string representation."""
        return f'IssuedCredentialModel(common_name={self.common_name})'

    def clean(self) -> None:
        """Validate that the device FK is set."""
        if self.device_id is None:
            raise ValidationError(_('device must be set.'))

    def revoke(self) -> None:
        """Revokes all active certificates associated with this credential."""
        domain = self.domain
        if domain is None or domain.issuing_ca is None:
            return
        ca = domain.issuing_ca
        cert: CertificateModel
        for cert in self.credential.certificates.all():
            status = cert.certificate_status
            if status in (CertificateModel.CertificateStatus.REVOKED, CertificateModel.CertificateStatus.EXPIRED):
                continue
            RevokedCertificateModel.objects.create(
                certificate=cert, revocation_reason=RevokedCertificateModel.ReasonCode.CESSATION, ca=ca
            )

    def pre_delete(self) -> None:
        """Revoke all active certificates and delete the credential."""
        self.revoke()
        self.credential.delete()  # this will also delete the IssuedCredentialModel via cascade

    def is_valid_domain_credential(self) -> tuple[bool, str]:
        """Determines if this issued credential is valid for enrolling new application credentials.

        This method performs the following checks:
          1. The IssuedCredentialModel type must be of type DOMAIN_CREDENTIAL.
          2. The credential must be of type ISSUED_CREDENTIAL.
          3. A primary certificate must exist.
          4. The certificate's status must be 'OK'.

        Returns:
            tuple[bool, str]: A tuple where:
                          - The first value is True if the credential meets all criteria, False otherwise.
                          - The second value is a reason string explaining why the credential is invalid.
        """
        if self.issued_credential_type != IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL:
            return False, 'Invalid issued credential type: Must be DOMAIN_CREDENTIAL.'

        result, reason = self.credential.is_valid_issued_credential()
        if not result:
            return False, reason

        return True, 'Valid domain credential.'

    @staticmethod
    def get_credential_for_certificate(cert: x509.Certificate) -> IssuedCredentialModel:
        """Retrieve an IssuedCredentialModel instance for the given certificate.

        :param cert: x509.Certificate to search for.
        :return: The corresponding IssuedCredentialModel instance.
        :raises DoesNotExist: if no matching issued credential is found.
        """
        cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        issued_credential = (
            IssuedCredentialModel.objects.filter(
                credential__certificates__sha256_fingerprint=cert_fingerprint,
            )
            .select_related('credential', 'device')
            .first()
        )

        if issued_credential is None:
            error_message = f'No issued credential found for certificate with fingerprint {cert_fingerprint}'
            raise IssuedCredentialModel.DoesNotExist(error_message)

        return issued_credential

    @staticmethod
    def get_credential_for_serial_number(
        domain: DomainModel, device: DeviceModel, serial_number: str
    ) -> IssuedCredentialModel:
        """Retrieve an IssuedCredentialModel instance for the given X.509 serial number within the specified domain.

        Raises: DoesNotExist if no matching issued credential is found.
        """
        from pki.models.credential import CredentialModel  # noqa: PLC0415

        credential_obj = CredentialModel.objects.filter(certificates__serial_number=serial_number).first()
        if not credential_obj:
            error_message = f'No credential found for certificate with serial {serial_number}'
            raise IssuedCredentialModel.DoesNotExist(error_message)

        try:
            issued_credential = IssuedCredentialModel.objects.get(
                credential=credential_obj, domain=domain, device=device
            )
        except IssuedCredentialModel.DoesNotExist:
            error_message = f'No issued credential found for certificate with serial {serial_number}'
            raise IssuedCredentialModel.DoesNotExist(error_message) from None

        return issued_credential


class RemoteIssuedCredentialModel(CustomDeleteActionModel):
    """Model for credentials issued to a CA, a DevOwnerID, or a device via a remote/RA CA."""

    class RemoteIssuedCredentialType(models.IntegerChoices):
        """The type of the credential."""

        DOMAIN_CREDENTIAL = 0, _('Domain Credential')
        DEV_OWNER_ID = 2, _('DevOwnerID')
        RA_DEVICE = 4, _('RA Device')

    id = models.AutoField(primary_key=True)

    common_name = models.CharField(verbose_name=_('Common Name'), max_length=255)
    issued_credential_type = models.IntegerField(
        choices=RemoteIssuedCredentialType,
        verbose_name=_('Credential Type'),
    )
    issued_using_cert_profile = models.CharField(
        max_length=255,
        verbose_name=_('Issued using Certificate Profile'),
        default='',
    )
    credential = models.OneToOneField(
        'pki.CredentialModel',
        verbose_name=_('Credential'),
        on_delete=models.CASCADE,
        related_name='remote_issued_credential',
        null=False,
        blank=False,
    )
    ca = models.ForeignKey(
        'pki.CaModel',
        verbose_name=_('CA'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )
    owner_credential = models.ForeignKey(
        'pki.OwnerCredentialModel',
        verbose_name=_('Owner Credential'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )
    device = models.ForeignKey(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )
    domain = models.ForeignKey(
        'pki.DomainModel',
        verbose_name=_('Domain'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Returns a human-readable string representation."""
        return f'RemoteIssuedCredentialModel(common_name={self.common_name})'

    def clean(self) -> None:
        """Validate that exactly one owner (ca, owner_credential, or device) is set."""
        owners = [self.ca_id, self.owner_credential_id, self.device_id]
        set_count = sum(1 for o in owners if o is not None)
        if set_count == 0:
            raise ValidationError(_('One of ca, owner_credential, or device must be set.'))
        if set_count > 1:
            raise ValidationError(_('Only one of ca, owner_credential, or device may be set.'))

    def pre_delete(self) -> None:
        """Delete the underlying credential (cascades back to this model)."""
        self.credential.delete()
