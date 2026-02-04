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

from pki.models import CaModel
from pki.models.certificate import CertificateModel, RevokedCertificateModel
from pki.models.credential import CredentialModel
from pki.models.domain import DomainModel
from pki.models.truststore import TruststoreModel
from util.db import CustomDeleteActionModel
from util.encrypted_fields import EncryptedCharField

if TYPE_CHECKING:
    from typing import Any

    from cryptography import x509


__all__ = [
    'DeviceModel',
    'IssuedCredentialModel',
    'RemoteDeviceCredentialDownloadModel',
]


class OnboardingStatus(models.IntegerChoices):
    """The onboarding status."""

    PENDING = 1, _('Pending')
    ONBOARDED = 2, _('Onboarded')


class OnboardingProtocol(models.IntegerChoices):
    """Choices of onboarding protocols."""

    MANUAL = 0, _('Manual Onboarding')
    CMP_IDEVID = 1, _('CMP - IDevID')
    CMP_SHARED_SECRET = 2, _('CMP - Shared Secret')
    EST_IDEVID = 3, _('EST - IDevID')
    EST_USERNAME_PASSWORD = 4, _('EST - Username & Password')
    AOKI = 5, _('AOKI')
    BRSKI = 6, _('BRSKI')


class OnboardingPkiProtocol(models.IntegerChoices):
    """Choices for onboarding pki protocols."""

    # Bitmask: Only use powers of 2: 1, 2, 4, 8, 16 ...
    CMP = 1, _('CMP')
    EST = 2, _('EST')


class NoOnboardingPkiProtocol(models.IntegerChoices):
    """Choices for no onboarding pki protocols."""

    # Bitmask: Only use powers of 2: 1, 2, 4, 8, 16 ...
    CMP_SHARED_SECRET = 1, _('CMP - Shared Secret (HMAC)')
    # 2 reserved for CMP Client Certificate
    EST_USERNAME_PASSWORD = 4, _('EST - Username & Password')
    # 8 reserved for EST Client Certificate
    MANUAL = 16, _('Manual')


class AbstractPkiProtocolModel[T: models.IntegerChoices]:
    """Extends a model for IntegerChoices stored as bitwise flags."""

    pki_protocol_class: type[T]

    def add_pki_protocol(self, pki_protocol: T) -> None:
        """Adds the provided PkiProtocol to the allowed protocols for onboarded devices.

        Args:
            pki_protocol: The PkiProtocol to allow.
        """
        self.pki_protocols |= pki_protocol.value

    def remove_pki_protocol(self, pki_protocol: T) -> None:
        """Removes the provided PkiProtocol from the allowed protocols if it is allowed..

        Args:
            pki_protocol: The PkiProtocol to forbid.
        """
        self.pki_protocols &= ~pki_protocol

    def clear_pki_protocols(self) -> None:
        """Clears all allowed PkiProtocols, that is, it deactivates application certificate issuance."""
        self.pki_protocols = 0

    def has_pki_protocol(self, pki_protocol: T) -> bool:
        """Checks if the provided PkiProtocol is allowed.

        Args:
            pki_protocol: The PkiProtocol that is checked against the allowed ones.

        Returns:
            Returns True if the provided PkiProtocol is allowed, False otherwise.
        """
        return (self.pki_protocols & pki_protocol) == pki_protocol

    def get_pki_protocols(self) -> list[T]:
        """Gets all allowed PkiProtocols.

        Returns:
            Retruns the allowed PkiProtocols as list.
        """
        return [pki_protocol for pki_protocol in self.pki_protocol_class if self.has_pki_protocol(pki_protocol)]

    def set_pki_protocols(self, pki_protocols: list[T]) -> None:
        """Sets all allowed PkiProtocols exactly matching the provided list."""
        self.clear_pki_protocols()
        for pki_protocol in pki_protocols:
            self.add_pki_protocol(pki_protocol)


class OnboardingConfigModel(AbstractPkiProtocolModel[OnboardingPkiProtocol], models.Model):
    """Onboarding Configuration Model."""

    pki_protocol_class = OnboardingPkiProtocol

    pki_protocols = models.PositiveIntegerField(
        verbose_name=_('Pki Protocol Bitwise Flag'), null=False, blank=True, default=0
    )

    onboarding_status = models.IntegerField(
        choices=OnboardingStatus,
        verbose_name=_('Onboarding Status'),
        null=False,
        blank=False,
        default=OnboardingStatus.PENDING,
    )

    onboarding_protocol = models.PositiveIntegerField(
        choices=OnboardingProtocol,
        verbose_name=_('Onboarding Protocol'),
        null=False,
        blank=False,
    )

    # these will be dropped after successfull onboarding
    est_password = EncryptedCharField(verbose_name=_('EST Password'), max_length=128, blank=True, default='')
    cmp_shared_secret = EncryptedCharField(verbose_name=_('CMP Shared Secret'), max_length=128, blank=True, default='')

    idevid_trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('IDevID Manufacturer Truststore'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    def __str__(self) -> str:
        """Gets the model instance as human-readable string."""
        return (
            'OnboardingConfigModel('
            f'onboarding_status:{OnboardingStatus(self.onboarding_status).label}, '
            f'onboarding_protocol:{OnboardingProtocol(self.onboarding_protocol).label}, '
            f'cmp_shared_secret:{bool(self.cmp_shared_secret)}, '
            f'est_password:{bool(self.est_password)})'
        )

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Executes full_clean() before saving.

        Args:
            *args: Positional arguments are passed to super().save().
            **kwargs: Keyword arguments are passed to super().save().
        """
        self.full_clean()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validation before saving the model."""
        error_messages = None

        match self.onboarding_protocol:
            case OnboardingProtocol.MANUAL:
                error_messages = self._validate_case_manual_onboarding()
            case OnboardingProtocol.CMP_IDEVID:
                error_messages = self._validate_case_cmp_idevid_onboarding()
            case OnboardingProtocol.CMP_SHARED_SECRET:
                error_messages = self._validate_case_cmp_shared_secret_onboarding()
            case OnboardingProtocol.EST_IDEVID:
                error_messages = self._validate_case_est_idevid_onboarding()
            case OnboardingProtocol.EST_USERNAME_PASSWORD:
                error_messages = self._validate_case_est_username_password_onboarding()
            case OnboardingProtocol.AOKI:
                err_msg = 'AOKI is not yet supported as onboarding protocol.'
                raise ValidationError(err_msg)
            case OnboardingProtocol.BRSKI:
                err_msg = 'BRSKI is not yet supported as onboarding protocol.'
                raise ValidationError(err_msg)
            case _:
                err_msg = f'Unknown onboarding protocol found: {self.onboarding_protocol}.'
                raise ValidationError(err_msg)

        if error_messages:
            raise ValidationError(error_messages)

    def _validate_case_manual_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.MANUAL.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for manual onboarding.'  # noqa: S105

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for manual onboarding.'  # noqa: S105

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = 'IDevID truststore must not be set for manual onboarding.'

        return error_messages

    def _validate_case_cmp_idevid_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.CMP_IDEVID.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        return {}

    def _validate_case_cmp_shared_secret_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.CMP_SHARED_SECRET.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for CMP shared-secret onboarding.'  # noqa: S105

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = 'IDevID truststore must not be set for CMP shared-secret onboarding.'

        return error_messages

    def _validate_case_est_idevid_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.EST_IDEVID.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for EST IDevID onboarding.'  # noqa: S105

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for EST IDevID onboarding.'  # noqa: S105

        # idevid_trust_store can be left blank while this would ofcourse mean no onboarding is possible.

        return error_messages

    def _validate_case_est_username_password_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.EST_USERNAME_PASSWORD.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = (
                'CMP shared-secret must not be set for EST username / password onboarding.'  # noqa: S105
            )

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = (
                'IDevID truststore must not be set for EST username / password onboarding.'
            )

        return error_messages


class NoOnboardingConfigModel(AbstractPkiProtocolModel[NoOnboardingPkiProtocol], models.Model):
    """No Onboarding Configuration Model."""

    pki_protocol_class = NoOnboardingPkiProtocol

    pki_protocols = models.PositiveIntegerField(
        verbose_name=_('Pki Protocol Bitwise Flag'), null=False, blank=True, default=0
    )
    est_password = models.CharField(verbose_name=_('EST Password'), max_length=128, blank=True, default='')
    cmp_shared_secret = models.CharField(verbose_name=_('CMP Shared Secret'), max_length=128, blank=True, default='')

    def __str__(self) -> str:
        """Gets the model instance as human-readable string."""
        return (
            'NoOnboardingConfigModel('
            f'cmp_shared_secret:{bool(self.cmp_shared_secret)}'
            f'est_password:{bool(self.est_password)})'
        )

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Executes full_clean() before saving.

        Args:
            *args: Positional arguments are passed to super().save().
            **kwargs: Keyword arguments are passed to super().save().
        """
        self.full_clean()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validation before saving the model."""
        error_messages = {}

        if self.cmp_shared_secret != '' and not self.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET):
            error_messages['cmp_shared_secret'] = (
                'CMP shared-secret must not be set if EST_USERNAME_PASSWORD is not enabled.'  # noqa: S105
            )

        if self.cmp_shared_secret == '' and self.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET):
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must be set if EST_USERNAME_PASSWORD is enabled.'  # noqa: S105

        if self.est_password != '' and not self.has_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD):
            error_messages['est_password'] = 'EST password must not be set if EST_USERNAME_PASSWORD is not enabled.'  # noqa: S105

        if self.est_password == '' and self.has_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD):
            error_messages['est_password'] = 'EST password must be set if EST_USERNAME_PASSWORD is enabled.'  # noqa: S105


class DeviceModel(CustomDeleteActionModel):
    """The DeviceModel."""

    common_name = models.CharField(_('Device'), max_length=100, default='', unique=True)
    serial_number = models.CharField(_('Serial-Number'), max_length=100, default='', blank=True, null=False)
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
        if not (self.onboarding_config or self.no_onboarding_config):
            err_msg = 'Either onboarding or no-onboarding has to be configured.'
            raise ValidationError(err_msg)

        if self.onboarding_config and self.no_onboarding_config:
            err_msg = 'Only one of onboarding or no-onboarding can be configured.'
            raise ValidationError(err_msg)


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
        cert: CertificateModel
        for cert in self.credential.certificates.all():
            status = cert.certificate_status
            if status in (CertificateModel.CertificateStatus.REVOKED, CertificateModel.CertificateStatus.EXPIRED):
                continue
            try:
                ca = CaModel.objects.get(credential__certificate__subject_public_bytes=cert.issuer_public_bytes)
            except CaModel.DoesNotExist:
                continue
            except CaModel.MultipleObjectsReturned:
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
