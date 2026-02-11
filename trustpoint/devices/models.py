"""This modules contains all models specific to the device abstractions."""

from __future__ import annotations

import datetime
import secrets
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta
from pyasn1_modules.rfc3280 import common_name  # type: ignore[import-untyped]

from onboarding.models import (
    AbstractPkiProtocolModel,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.credential import CredentialModel
from pki.models.domain import DomainModel
from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    from typing import Any

    from cryptography import x509


__all__ = [
    'AbstractPkiProtocolModel',
    'DeviceModel',
    'IssuedCredentialModel',
    'NoOnboardingConfigModel',
    'NoOnboardingPkiProtocol',
    'OnboardingConfigModel',
    'OnboardingPkiProtocol',
    'OnboardingProtocol',
    'OnboardingStatus',
    'RemoteDeviceCredentialDownloadModel',
]


class DeviceModel(CustomDeleteActionModel):
    """The DeviceModel."""

    common_name = models.CharField(_('Device'), max_length=100, default='', unique=True)
    serial_number = models.CharField(_('Serial-Number'), max_length=100, default='', blank=True, null=False)
    ip_address = models.GenericIPAddressField(_('IP Address'), protocol='both', unpack_ipv4=True, null=True, blank=True)
    opc_server_port = models.PositiveIntegerField(_('OPC Server Port'), default=0, blank=True, null=False)
    domain = models.ForeignKey(
        DomainModel, verbose_name=_('Domain'), related_name='devices', blank=True, null=True, on_delete=models.PROTECT
    )

    onboarding_config = models.ForeignKey(
        OnboardingConfigModel,
        verbose_name=_('Onboarding Config'),
        related_name='device',
        blank=True,
        null=True,
        on_delete=models.PROTECT,
    )
    no_onboarding_config = models.ForeignKey(
        NoOnboardingConfigModel,
        verbose_name=_('No Onboarding Config'),
        related_name='device',
        blank=True,
        null=True,
        on_delete=models.PROTECT,
    )

    class DeviceType(models.IntegerChoices):
        """Enum for device type."""

        GENERIC_DEVICE = 0, _('Generic Device')
        OPC_UA_GDS = 1, _('OPC UA GDS')
        OPC_UA_GDS_PUSH = 2, _('OPC UA GDS Push')

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
        self.issued_credentials.all().delete()

    @property
    def est_username(self) -> str:
        """Gets the EST username."""
        return self.common_name

    def clean(self) -> None:
        """Validation before saving the model."""
        error_messages = {}

        if not (self.onboarding_config or self.no_onboarding_config):
            error_messages['onboarding_config'] = 'Either onboarding or no-onboarding has to be configured.'

        if self.onboarding_config and self.no_onboarding_config:
            error_messages['onboarding_config'] = 'Only one of onboarding or no-onboarding can be configured.'

        if self.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH:
            if not self.onboarding_config:
                error_messages['device_type'] = 'OPC UA GDS Push devices must use onboarding configuration.'
            elif self.onboarding_config.onboarding_protocol != OnboardingProtocol.OPC_GDS_PUSH:
                error_messages['device_type'] = 'OPC UA GDS Push devices must use OPC_GDS_PUSH onboarding protocol.'

            if not self.ip_address:
                error_messages['ip_address'] = 'OPC UA GDS Push devices must have an IP address.'

            if not self.opc_server_port or self.opc_server_port == 0:
                error_messages['opc_server_port'] = 'OPC UA GDS Push devices must have a valid OPC server port.'

        if error_messages:
            raise ValidationError(error_messages)


class IssuedCredentialModel(CustomDeleteActionModel):
    """Model for all credentials and certificates that have been issued or requested by the Trustpoint."""

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
        CredentialModel,
        verbose_name=_('Credential'),
        on_delete=models.CASCADE,
        related_name='issued_credential',
        null=False,
        blank=False,
    )
    device = models.ForeignKey(
        'devices.DeviceModel', verbose_name=_('Device'), on_delete=models.PROTECT, related_name='issued_credentials'
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
        if self.domain.issuing_ca is None:
            return
        ca = self.domain.issuing_ca
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

    @staticmethod
    def get_credential_for_serial_number(
        domain: DomainModel, device: DeviceModel, serial_number: str
    ) -> IssuedCredentialModel:
        """Retrieve an IssuedCredentialModel instance for the given X.509 serial number within the specified domain.

        Raises: DoesNotExist if no matching issued credential is found.
        """
        credential = CredentialModel.objects.filter(certificates__serial_number=serial_number).first()
        if not credential:
            error_message = f'No credential found for certificate with serial {serial_number}'
            raise IssuedCredentialModel.DoesNotExist(error_message)

        try:
            issued_credential = IssuedCredentialModel.objects.get(credential=credential, domain=domain, device=device)
        except IssuedCredentialModel.DoesNotExist:
            error_message = f'No issued credential found for certificate with serial {serial_number}'
            raise IssuedCredentialModel.DoesNotExist(error_message) from None

        return issued_credential


class RemoteDeviceCredentialDownloadModel(models.Model):
    """Model to associate a credential model with an OTP and token for unauthenticated remoted download."""

    BROWSER_MAX_OTP_ATTEMPTS = 3
    TOKEN_VALIDITY = datetime.timedelta(minutes=3)

    issued_credential_model = models.OneToOneField(IssuedCredentialModel, on_delete=models.CASCADE)
    otp = models.CharField(_('OTP'), max_length=32, default='')
    device = models.ForeignKey('devices.DeviceModel', on_delete=models.CASCADE)
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
            if self.attempts >= self.BROWSER_MAX_OTP_ATTEMPTS:
                self.otp = '-'
                self.delete()
            else:
                self.save()
            return False
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
