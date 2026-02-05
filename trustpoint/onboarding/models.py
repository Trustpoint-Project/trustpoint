"""This module contains models related to onboarding configurations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from pki.models.truststore import TruststoreModel
from util.encrypted_fields import EncryptedCharField

if TYPE_CHECKING:
    from typing import Any


__all__ = [
    'AbstractPkiProtocolModel',
    'NoOnboardingConfigModel',
    'NoOnboardingPkiProtocol',
    'OnboardingConfigModel',
    'OnboardingPkiProtocol',
    'OnboardingProtocol',
    'OnboardingStatus',
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
    OPC_GDS_PUSH = 7, _('OPC - GDS Push')


class OnboardingPkiProtocol(models.IntegerChoices):
    """Choices for onboarding pki protocols."""

    # Bitmask: Only use powers of 2: 1, 2, 4, 8, 16 ...
    CMP = 1, _('CMP')
    EST = 2, _('EST')
    OPC_GDS_PUSH = 4, _('OPC - GDS Push')


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

    opc_user = models.CharField(verbose_name=_('OPC User'), max_length=128, blank=True, default='')
    opc_password = EncryptedCharField(verbose_name=_('OPC Password'), max_length=128, blank=True, default='')

    idevid_trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('IDevID Manufacturer Truststore'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='idevid_onboarding_configs',
    )

    opc_trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('OPC Server Truststore'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='opc_onboarding_configs',
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
            case OnboardingProtocol.OPC_GDS_PUSH:
                error_messages = self._validate_case_opc_gds_push_onboarding()
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

    def _validate_case_opc_gds_push_onboarding(self) -> dict[str, str]:
        """Validates case OnboardingProtocol.OPC_GDS_PUSH.

        Args:
            error_messages: The container that gathers all error messages.

        Returns:
            The error_messages gathered.
        """
        error_messages = {}

        if self.est_password != '':
            error_messages['est_password'] = 'EST password must not be set for OPC - GDS Push onboarding.'  # noqa: S105

        if self.cmp_shared_secret != '':
            error_messages['cmp_shared_secret'] = 'CMP shared-secret must not be set for OPC - GDS Push onboarding.'  # noqa: S105

        if self.idevid_trust_store is not None:
            error_messages['idevid_trust_store'] = 'IDevID truststore must not be set for OPC - GDS Push onboarding.'

        allowed_protocols = self.get_pki_protocols()
        if len(allowed_protocols) != 1 or OnboardingPkiProtocol.OPC_GDS_PUSH not in allowed_protocols:
            error_messages['pki_protocols'] = 'OPC - GDS Push onboarding must use only the OPC_GDS_PUSH PKI protocol.'

        return error_messages

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

    trust_store = models.ForeignKey(
        TruststoreModel,
        verbose_name=_('Trust Store'),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='no_onboarding_configs',
        help_text=_('Trust store containing certificates to verify the remote server'),
    )

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

        if error_messages:
            raise ValidationError(error_messages)
