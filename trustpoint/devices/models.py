"""This modules contains all models specific to the device abstractions."""

from __future__ import annotations

import datetime
import logging
import secrets
from typing import TYPE_CHECKING

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.credential import CredentialModel
from pki.models.domain import DomainModel
from pki.models.issuing_ca import IssuingCaModel
from pki.models.truststore import TruststoreModel
from pyasn1_modules.rfc3280 import common_name  # type: ignore[import-untyped]
from trustpoint_core import oid  # type: ignore[import-untyped]
from util.db import IndividualDeleteManager, SelfProtectOneToOneField
from util.field import UniqueNameValidator

if TYPE_CHECKING:
    from typing import Any

    from pki.models.certificate import CertificateModel

logger = logging.getLogger(__name__)

__all__ = [
    'DeviceModel',
    'IssuedCredentialModel',
    'RemoteDeviceCredentialDownloadModel',
]


class DeviceModel(models.Model):
    """The DeviceModel."""

    objects: IndividualDeleteManager[DeviceModel]

    id = models.AutoField(primary_key=True)
    unique_name = models.CharField(
        _('Device'), max_length=100, unique=True, default='New-Device', validators=[UniqueNameValidator()]
    )
    serial_number = models.CharField(_('Serial-Number'), max_length=100)
    domain = models.ForeignKey(
        DomainModel, verbose_name=_('Domain'), related_name='devices', blank=True, null=True, on_delete=models.PROTECT
    )

    domain_credential_onboarding = models.BooleanField(
        verbose_name=_('Domain Credential Onboarding'), default=True, blank=False, null=False
    )

    class OnboardingStatus(models.IntegerChoices):
        """The onboarding status."""

        NO_ONBOARDING = 0, _('No Onboarding')
        PENDING = 1, _('Pending')
        ONBOARDED = 2, _('Onboarded')

    onboarding_status = models.IntegerField(
        choices=OnboardingStatus,
        verbose_name=_('Onboarding Status'),
        default=OnboardingStatus.NO_ONBOARDING,
        null=False,
    )

    class OnboardingProtocol(models.IntegerChoices):
        """Choices of onboarding protocols."""

        NO_ONBOARDING = 0, _('No Onboarding')
        EST_PASSWORD = 1, _('EST - Username & Password')
        EST_IDEVID = 2, _('EST - IDevID')
        CMP_SHARED_SECRET = 3, _('CMP - Shared Secret')
        CMP_IDEVID = 4, _('CMP - IDevID')
        AOKI = 5, _('AOKI')
        BRSKI = 6, _('BRSKI')

    onboarding_protocol = models.IntegerField(
        choices=OnboardingProtocol,
        verbose_name=_('Onboarding Protocol'),
        null=False,
        default=OnboardingProtocol.NO_ONBOARDING,
    )

    class PkiProtocol(models.IntegerChoices):
        """Choices of pki protocols."""

        MANUAL = 0, _('Manual Download')
        EST_PASSWORD = 1, _('EST - Username & Password')
        EST_CLIENT_CERTIFICATE = 2, _('EST - LDevID')
        CMP_SHARED_SECRET = 3, _('CMP - Shared Secret')
        CMP_CLIENT_CERTIFICATE = 4, _('CMP - LDevID')

    pki_protocol = models.IntegerField(
        choices=PkiProtocol, verbose_name=_('Pki Protocol'), null=False, default=PkiProtocol.MANUAL
    )

    est_password = models.CharField(verbose_name=_('EST Password'), max_length=128, blank=True, default='')
    cmp_shared_secret = models.CharField(verbose_name=_('CMP Shared Secret'), max_length=128, blank=True, default='')

    idevid_trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('IDevID Manufacturer Truststore'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    objects = IndividualDeleteManager()

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Returns a human-readable string representation."""
        return f'DeviceModel(unique_name={self.unique_name})'

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Delete all issued credentials for this device before deleting the device itself."""
        logger.info(f'Deleting all issued credentials for device {self.unique_name}') # noqa: G004
        self.issued_credentials.all().delete()
        return super().delete(*args, **kwargs)

    @property
    def est_username(self) -> str:
        """Gets the EST username."""
        return self.unique_name

    @property
    def signature_suite(self) -> oid.SignatureSuite:
        """Gets the corresponding SignatureSuite object."""
        return oid.SignatureSuite.from_certificate(
            self.domain.issuing_ca.credential.get_certificate_serializer().as_crypto()
        )

    @property
    def public_key_info(self) -> oid.PublicKeyInfo:
        """Gets the corresponding PublicKeyInfo object."""
        return self.signature_suite.public_key_info


class IssuedCredentialModel(models.Model):
    """Model for all credentials and certificates that have been issued or requested by the Trustpoint."""

    objects: IndividualDeleteManager[IssuedCredentialModel]

    class IssuedCredentialType(models.IntegerChoices):
        """The type of the credential."""

        DOMAIN_CREDENTIAL = 0, _('Domain Credential')
        APPLICATION_CREDENTIAL = 1, _('Application Credential')

    class IssuedCredentialPurpose(models.IntegerChoices):
        """The purpose of the issued credential."""

        DOMAIN_CREDENTIAL = 0, _('Domain Credential')
        GENERIC = 1, _('Generic')
        TLS_CLIENT = 2, _('TLS-Client')
        TLS_SERVER = 3, _('TLS-Server')
        OPCUA_CLIENT = 4, _('OpcUa-Client')
        OPCUA_SERVER = 5, _('OpcUa-Server')

    id = models.AutoField(primary_key=True)

    common_name = models.CharField(verbose_name=_('Common Name'), max_length=255)
    issued_credential_type = models.IntegerField(choices=IssuedCredentialType, verbose_name=_('Credential Type'))
    issued_credential_purpose = models.IntegerField(
        choices=IssuedCredentialPurpose, verbose_name=_('Credential Purpose')
    )
    credential = SelfProtectOneToOneField(
        CredentialModel,
        verbose_name=_('Credential'),
        on_delete=models.CASCADE,
        related_name='issued_credential',
        null=False,
        blank=False,
    )
    device = models.ForeignKey(
        DeviceModel, verbose_name=_('Device'), on_delete=models.PROTECT, related_name='issued_credentials'
    )
    domain = models.ForeignKey(
        DomainModel, verbose_name=_('Domain'), on_delete=models.PROTECT, related_name='issued_credentials'
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    objects = IndividualDeleteManager()

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Returns a human-readable string representation."""
        return f'IssuedCredentialModel(common_name={common_name})'

    def revoke(self) -> None:
        """Revokes all active certificates associated with this credential."""
        cert: CertificateModel
        for cert in self.credential.certificates.all():
            status = cert.certificate_status
            if (status in (CertificateModel.CertificateStatus.REVOKED, CertificateModel.CertificateStatus.EXPIRED)):
                continue
            try:
                ca = IssuingCaModel.objects.get(
                    credential__certificate__subject_public_bytes = cert.issuer_public_bytes
                )
            except IssuingCaModel.DoesNotExist:
                logger.exception(
                    f'Cannot revoke certificate {cert} because its corresponding Issuing CA was not found.')  # noqa: G004
                continue
            except IssuingCaModel.MultipleObjectsReturned:
                logger.exception(
                    f'Cannot revoke certificate {cert} because multiple CAs were found with the same subject bytes.')  # noqa: G004
                continue

            RevokedCertificateModel.objects.create(
                certificate=cert,
                revocation_reason=RevokedCertificateModel.ReasonCode.CESSATION,
                ca=ca
            )

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Delete the credential and the issued credential."""
        self.revoke()
        self.credential.delete()  # this will also delete the IssuedCredentialModel via cascade
        return super().delete(*args, **kwargs)


class RemoteDeviceCredentialDownloadModel(models.Model):
    """Model to associate a credential model with an OTP and token for unauthenticated remoted download."""

    objects: models.Manager[RemoteDeviceCredentialDownloadModel]

    BROWSER_MAX_OTP_ATTEMPTS = 3
    TOKEN_VALIDITY = datetime.timedelta(minutes=3)

    issued_credential_model = models.OneToOneField(IssuedCredentialModel, on_delete=models.CASCADE)
    otp = models.CharField(_('OTP'), max_length=32, default='')
    device = models.ForeignKey(DeviceModel, on_delete=models.CASCADE)
    attempts = models.IntegerField(_('Attempts'), default=0)
    download_token = models.CharField(_('Download Token'), max_length=64, default='')
    token_created_at = models.DateTimeField(_('Token Created'), null=True)

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Return a string representation of the model."""
        return f'RemoteDeviceCredentialDownloadModel(credential={self.issued_credential_model.id})'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Generates a new random OTP on initial save of the model."""
        if not self.otp:
            self.otp = secrets.token_urlsafe(8)
        super().save(*args, **kwargs)

    def get_otp_display(self) -> str:
        """Return the OTP in the format 'credential_id.otp' for display within the admin view.

        Returns:
            The str to display.
        """
        if not self.otp or self.otp == '-':
            return 'OTP no longer valid'
        return f'{self.issued_credential_model.id}.{self.otp}'

    def check_otp(self, otp: str) -> bool:
        """Check if the provided OTP matches the stored OTP.

        Args:
            otp: The OTP to check.

        Returns:
            True if the OTP is valid, False otherwise.
        """
        if not self.otp or self.otp == '-':
            return False
        matches = otp == self.otp
        if not matches:
            self.attempts += 1
            log_msg = (
                f'Incorrect OTP attempt {self.attempts} for browser credential download '
                f'for device {self.device.unique_name} (credential id={self.issued_credential_model.id})'
            )
            logger.warning(log_msg)

            if self.attempts >= self.BROWSER_MAX_OTP_ATTEMPTS:
                self.otp = '-'
                self.delete()
                logger.warning('Too many incorrect OTP attempts. Download invalidated.')
            else:
                self.save()
            return False

        log_msg = (
            f'Correct OTP entered for browser credential download for device {self.device.unique_name}'
            f'(credential id={self.issued_credential_model.id})'
        )
        logger.info(log_msg)
        self.otp = '-'
        self.download_token = secrets.token_urlsafe(32)
        self.token_created_at = timezone.now()
        self.save()
        return True

    def check_token(self, token: str) -> bool:
        """Check if the provided token matches the stored token and whether it is still valid.

        Args:
            token: The token to check.

        Returns:
            True if the token is valid, false otherwise.
        """
        if not self.download_token or not self.token_created_at:
            return False
        if timezone.now() - self.token_created_at > self.TOKEN_VALIDITY:
            self.delete()
            return False

        return token == self.download_token
