"""This modules contains all models specific to the device abstractions."""

from __future__ import annotations

import datetime
import logging
import secrets
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
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
from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    from typing import Any

    from cryptography import x509

logger = logging.getLogger(__name__)

__all__ = [
    'DeviceModel',
    'IssuedCredentialModel',
    'RemoteDeviceCredentialDownloadModel',
]


class DeviceModel(CustomDeleteActionModel):
    """The DeviceModel."""

    id = models.AutoField(primary_key=True)
    common_name = models.CharField(_('Device'), max_length=100, default='New-Device')
    serial_number = models.CharField(_('Serial-Number'), max_length=100, default='', blank=True, null=False)
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

    class DeviceType(models.IntegerChoices):
        """Enum for device type."""

        GENERIC_DEVICE = 0, _('Generic Device')
        OPC_UA_GDS = 1, _('OPC UA GDS')

    device_type = models.IntegerField(
        choices=DeviceType,
        verbose_name=_('Device Type'),
        default=DeviceType.GENERIC_DEVICE,
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    def __str__(self) -> str:
        """Returns a human-readable string representation."""
        return f'DeviceModel(common_name={self.common_name})'

    def pre_delete(self) -> None:
        """Delete all issued credentials for this device before deleting the device itself."""
        logger.info(f'Deleting all issued credentials for device {self.common_name}')  # noqa: G004
        self.issued_credentials.all().delete()

    @property
    def est_username(self) -> str:
        """Gets the EST username."""
        return self.common_name

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


class IssuedCredentialModel(CustomDeleteActionModel):
    """Model for all credentials and certificates that have been issued or requested by the Trustpoint."""

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
    credential = models.OneToOneField(
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
            if status in (CertificateModel.CertificateStatus.REVOKED, CertificateModel.CertificateStatus.EXPIRED):
                continue
            try:
                ca = IssuingCaModel.objects.get(credential__certificate__subject_public_bytes=cert.issuer_public_bytes)
            except IssuingCaModel.DoesNotExist:
                logger.exception(
                    'Cannot revoke certificate %s because its corresponding Issuing CA was not found.', cert
                )
                continue
            except IssuingCaModel.MultipleObjectsReturned:
                logger.exception(
                    'Cannot revoke certificate %s because multiple CAs were found with the same subject bytes.', cert
                )
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
        :raises ClientCertificateAuthenticationError: if no matching issued credential is found.
        """
        cert_fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        credential = CredentialModel.objects.filter(certificates__sha256_fingerprint=cert_fingerprint).first()
        if not credential:
            error_message = f'No credential found for certificate with fingerprint {cert_fingerprint}'
            raise IssuedCredentialModel.DoesNotExist(error_message)

        try:
            issued_credential = IssuedCredentialModel.objects.get(credential=credential)
        except IssuedCredentialModel.DoesNotExist:
            error_message = f'No issued credential found for certificate with fingerprint {cert_fingerprint}'
            raise IssuedCredentialModel.DoesNotExist(error_message) from None

        return issued_credential


class RemoteDeviceCredentialDownloadModel(models.Model):
    """Model to associate a credential model with an OTP and token for unauthenticated remoted download."""

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
            logger.warning(
                'Incorrect OTP attempt %s for browser credential download for device %s (credential id=%i)',
                self.attempts,
                self.device.common_name,
                self.issued_credential_model.id,
            )

            if self.attempts >= self.BROWSER_MAX_OTP_ATTEMPTS:
                self.otp = '-'
                self.delete()
                logger.warning('Too many incorrect OTP attempts. Download invalidated.')
            else:
                self.save()
            return False

        logger.info(
            'Correct OTP entered for browser credential download for device %s(credential id=%i)',
            self.device.common_name,
            self.issued_credential_model.id,
        )
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
