"""This modules contains all models specific to the device abstractions."""

from __future__ import annotations

import datetime
import secrets
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_q.tasks import schedule  # type: ignore[import-untyped]
from django_stubs_ext.db.models import TypedModelMeta

from onboarding.models import (
    AbstractPkiProtocolModel,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
)
from pki.models.domain import DomainModel
from pki.models.issued_credential import IssuedCredentialModel
from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    from typing import Any


__all__ = [
    'AbstractPkiProtocolModel',
    'DeviceModel',
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
    rfc_4122_uuid = models.UUIDField(
        _('Device UUID'),
        default=uuid.uuid4,
        unique=True,
        editable=False,
        help_text=_(
            'RFC 4122 version 4 UUID uniquely identifying this device. '
            'Auto-generated on device creation and immutable thereafter.'
        ),
    )
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

    opc_gds_push_enable_periodic_update = models.BooleanField(
        _('Enable Periodic Certificate and Trustlist Update'),
        default=False,
        blank=True,
        null=False,
        help_text=_(
            'When enabled, the server certificate and trustlist will be automatically '
            'renewed at the specified interval.'
        ),
    )
    opc_gds_push_renewal_interval = models.PositiveIntegerField(
        _('Renewal Interval (hours)'),
        default=168,
        blank=True,
        null=False,
        help_text=_(
            'Number of hours between each automatic server certificate and trustlist renewal. Minimum 1 hour.'
        ),
    )
    opc_gds_push_last_update_scheduled_at = models.DateTimeField(
        _('Last Periodic Update Scheduled At'),
        null=True,
        blank=True,
        help_text=_(
            'Timestamp of the most recent scheduled periodic server certificate and trustlist update.'
        ),
    )

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

    @property
    def rfc_4122_uuid_str(self) -> str:
        """Get the lowercase hyphenated RFC 4122 version 4 UUID string.

        The returned value conforms to the following requirements:
        - Lowercase hex with hyphens
        - Not predictable or sequential
        - Remains unchanged when the device is rebound to new hardware

        Returns:
            The UUID as a lowercase hyphenated string (e.g. '550e8400-e29b-41d4-a716-446655440000').
        """
        return str(self.rfc_4122_uuid)

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

            if self.opc_gds_push_enable_periodic_update and self.opc_gds_push_renewal_interval < 1:
                error_messages['opc_gds_push_renewal_interval'] = (
                    'Renewal interval must be at least 1 hour.'
                )

        if error_messages:
            raise ValidationError(error_messages)

    def schedule_next_gds_push_update(self) -> None:
        """Schedule the next periodic GDS Push server certificate and trustlist update using Django-Q2.

        Creates a one-off scheduled task in Django-Q2 that will execute at the calculated time
        based on the configured renewal interval. Does nothing when periodic updates are disabled
        or the device is not of type OPC UA GDS Push.
        """
        scheduled_time = timezone.now() + timedelta(hours=self.opc_gds_push_renewal_interval)

        schedule(
            'devices.tasks.perform_gds_push_update',
            self.pk,
            schedule_type='O',
            next_run=scheduled_time,
            name=f'gds_push_update_{self.pk}_{scheduled_time.timestamp()}',
        )

        self.opc_gds_push_last_update_scheduled_at = scheduled_time
        self.save(update_fields=['opc_gds_push_last_update_scheduled_at'])


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
