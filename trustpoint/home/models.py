"""Module that contains all models corresponding to the devices app."""

from __future__ import annotations

import logging
from typing import Any

from devices.models import DeviceModel
from django.db import models
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from pki.models.certificate import CertificateModel
from pki.models.domain import DomainModel
from pki.models.issuing_ca import IssuingCaModel

log = logging.getLogger('tp.home')


class NotificationStatus(models.Model):
    """Model representing a status a notification can have."""

    objects: models.Manager[NotificationStatus]

    class StatusChoices(models.TextChoices):
        """Status Types"""

        NEW = 'NEW', _('New')
        CONFIRMED = 'CONF', _('Confirmed')
        IN_PROGRESS = 'PROG', _('In Progress')
        SOLVED = 'SOLV', _('Solved')
        NOT_SOLVED = 'NOSOL', _('Not Solved')
        ESCALATED = 'ESC', _('Escalated')
        SUSPENDED = 'SUS', _('Suspended')
        REJECTED = 'REJ', _('Rejected')
        DELETED = 'DEL', _('Deleted')
        CLOSED = 'CLO', _('Closed')
        ACKNOWLEDGED = 'ACK', _('Acknowledged')
        FAILED = 'FAIL', _('Failed')
        EXPIRED = 'EXP', _('Expired')
        PENDING = 'PEND', _('Pending')

    status = models.CharField(max_length=20, choices=StatusChoices, unique=True)

    def __str__(self) -> str:
        """Returns a human-readable string."""
        return str(self.get_status_display())


class NotificationMessageModel(models.Model):
    """Message Model for Notifications with Short and Optional Long Descriptions."""

    short_description = models.CharField(max_length=255)
    long_description = models.CharField(max_length=65536, default='No description provided')

    def __str__(self) -> str:
        """Returns a human-readable string."""
        return self.short_description[:50]


class NotificationMessage:
    """Class for notification content with short and optional long descriptions."""

    short_description: str
    long_description: str = 'No description provided'

    def __init__(self, short_description: str, long_description: str = 'No description provided') -> None:
        """Initializes a NotificationMessageModel instance."""
        self.short_description = short_description
        self.long_description = long_description

    def __str__(self) -> str:
        """Returns a human-readable string."""
        return self.short_description[:50]

    @property
    def short(self) -> str:
        """Returns the short description."""
        return self.short_description

    @property
    def long(self) -> str:
        """Returns the long description."""
        return self.long_description


class NotificationModel(models.Model):
    """Notifications Model."""

    objects: models.Manager[NotificationModel]

    class NotificationTypes(models.TextChoices):
        """Supported Notification Types."""

        SETUP = 'SET', _('SETUP')
        INFO = 'INF', _('INFO')
        WARNING = 'WAR', _('WARNING')
        CRITICAL = 'CRI', _('CRITICAL')

    class NotificationSource(models.TextChoices):
        """Origin of the Notification."""

        SYSTEM = 'S', _('System')
        DOMAIN = 'D', _('Domain')
        DEVICE = 'E', _('Device')
        ISSUING_CA = 'I', _('Issuing CA')
        CERTIFICATE = 'C', _('Certificate')

    class NotificationMessageType(models.TextChoices):
        """Types of messages (aka. unique strings to that particular notification)."""

        CUSTOM = 'C', 'custom'  # custom message, i.e. strings are stored in the database. Can not be translated.
        # Test notifications, generated by create_notifications.py
        ISSUING_CA_TEST = 'TEST_CA'
        DOMAIN_TEST = 'TEST_DOMAIN'
        CERT_TEST = 'TEST_CERT'
        DEVICE_TEST = 'TEST_DEVICE'
        # Welcome notifications
        WELCOME_POPULATE_TEST_DATA = 'POP_TEST_DATA'
        TRUSTPOINT_DOCUMENTATION = 'TP_DOCS'
        TRUSTPOINT_PROJECT_INFO = 'TP_INFO'
        WELCOME_MESSAGE = 'WELCOME'
        # Periodic task notifications
        SYSTEM_NOT_HEALTHY = 'SYS_NOT_HEALTHY'
        VULNERABILITY = 'VULNERABILITY'
        CERT_EXPIRING = 'CERT_EXPIRING'
        CERT_EXPIRED = 'CERT_EXPIRED'
        ISSUING_CA_EXPIRING = 'CA_EXPIRING'
        ISSUING_CA_EXPIRED = 'CA_EXPIRED'
        DOMAIN_NO_ISSUING_CA = 'DOMAIN_NO_CA'
        DEVICE_NOT_ONBOARDED = 'DEV_NOT_ONBRD'
        DEVICE_ONBOARDING_FAILED = 'DEV_ONBRD_FAIL'
        DEVICE_CERT_REVOKED = 'DEV_CERT_REV'
        WEAK_SIGNATURE_ALGORITHM = 'WEAK_SIG_ALGO'
        INSUFFICIENT_KEY_LENGTH = 'INSUFF_KEY_LEN'
        WEAK_ECC_CURVE = 'WEAK_ECC_CURVE'

        def get_message(self) -> NotificationMessage:
            """Returns the message for the given type."""
            message_dict = {
                self.CUSTOM: NotificationMessage(force_str(_('Custom Message'))),
                # Test notifications, generated by create_notifications.py
                self.ISSUING_CA_TEST: NotificationMessage(
                    force_str(_('Test for Issuing CA: {ca}')),
                    force_str(_('Notification for Issuing CA: {ca}'))
                ),
                self.DOMAIN_TEST: NotificationMessage(
                    force_str(_('Test for Domain: {domain}')),
                    force_str(_('Notification for Domain: {domain}'))
                ),
                self.CERT_TEST: NotificationMessage(
                    force_str(_('Test for Certificate: {cn}')),
                    force_str(_('Notification for Certificate: Common Name {cn} with Serial Number {sn}')),
                ),
                self.DEVICE_TEST: NotificationMessage(
                    force_str(_('Test for Device: {device}')),
                    force_str(_('Notification for Device: {device}'))
                ),
                # Welcome notifications
                self.WELCOME_POPULATE_TEST_DATA: NotificationMessage(
                    force_str(_('Populate test data')),
                    force_str(_('Click <a href="{url}">here</a> to add test issuing CAs, domains and devices.')),
                ),
                self.TRUSTPOINT_DOCUMENTATION: NotificationMessage(
                    force_str(_('Access the Trustpoint Documentation')),
                    force_str(_('You can find the official Trustpoint documentation here: {link}')),
                ),
                self.TRUSTPOINT_PROJECT_INFO: NotificationMessage(
                    force_str(_('Explore the Trustpoint project')),
                    force_str(_(
                        'Visit the Trustpoint GitHub repository for more information: '
                        '<a href="{url_github}" target="_blank">Trustpoint GitHub</a><br>'
                        'Learn more about industrial security and the Trustpoint project on our '
                        '<a href="{url_homepage}" target="_blank">homepage</a>'
                    )),
                ),
                self.WELCOME_MESSAGE: NotificationMessage(
                    force_str(_('Welcome to Trustpoint!')),
                    force_str(_(
                        'Thank you for setting up Trustpoint. '
                        'This system will help you manage your certificates and secure your environment.'
                    )),
                ),
                # Periodic task notifications
                self.SYSTEM_NOT_HEALTHY: NotificationMessage(
                    force_str(_('System health check failed')),
                    force_str(_(
                        'The system health check detected an issue with one or more services. '
                        'Please investigate immediately.'
                    )),
                ),
                self.VULNERABILITY: NotificationMessage(
                    force_str(_('Security vulnerability detected')),
                    force_str(_(
                        'A security vulnerability affecting system components has been detected. '
                        'Immediate attention required.'
                    )),
                ),
                self.CERT_EXPIRING: NotificationMessage(
                    force_str(_('Certificate {common_name} is expiring soon')),
                    force_str(_('The certificate {common_name} is set to expire on {not_valid_after}.')),
                ),
                self.CERT_EXPIRED: NotificationMessage(
                    force_str(_('Certificate {common_name} has expired')),
                    force_str(_('The certificate {common_name} expired on {not_valid_after}.')),
                ),
                self.ISSUING_CA_EXPIRING: NotificationMessage(
                    force_str(_('Issuing CA {unique_name} is expiring soon')),
                    force_str(_('The issuing CA {unique_name} is set to expire on {not_valid_after}.')),
                ),
                self.ISSUING_CA_EXPIRED: NotificationMessage(
                    force_str(_('Issuing CA {unique_name} has expired')),
                    force_str(_('The issuing CA {unique_name} expired on {not_valid_after}.')),
                ),
                self.DOMAIN_NO_ISSUING_CA: NotificationMessage(
                    force_str(_('Domain {unique_name} has no Issuing CA assigned')),
                    force_str(_('The domain {unique_name} currently has no Issuing CA assigned.')),
                ),
                self.DEVICE_NOT_ONBOARDED: NotificationMessage(
                    force_str(_('Device {device} is not onboarded in {domain}')),
                    force_str(_('The device {device} has not completed onboarding.')),
                ),
                self.DEVICE_ONBOARDING_FAILED: NotificationMessage(
                    force_str(_('Device {device} onboarding failed')),
                    force_str(_('The device {device} failed onboarding.'))
                ),
                self.DEVICE_CERT_REVOKED: NotificationMessage(
                    force_str(_('Device {device} certificate revoked')),
                     force_str(_('The device {device} has had its certificate revoked and may no longer be trusted.')),
                ),
                self.WEAK_SIGNATURE_ALGORITHM: NotificationMessage(
                    force_str(_('Certificate {common_name} uses a weak signature algorithm')),
                    force_str(_('The certificate {common_name} is signed using {signature_algorithm}, '
                                'which is considered weak.')),
                ),
                self.INSUFFICIENT_KEY_LENGTH: NotificationMessage(
                    force_str(_('Certificate {common_name} uses insufficient key length')),
                    force_str(_(
                        'The certificate {common_name} uses an RSA key size of {spki_key_size} bits, '
                        'which is less than the recommended 2048 bits.'
                    )),
                ),
                self.WEAK_ECC_CURVE: NotificationMessage(
                    force_str(_('Certificate {common_name} uses a weak ECC curve')),
                    force_str(_(
                        'The certificate {common_name} is using the {spki_ec_curve} ECC curve, '
                        'which is no longer recommended.'
                    )),
                ),
            }

            default = NotificationMessage(
                force_str(_('Unknown Notification message string.')),
                _('Guess we messed up. Type of this notification is %(type)s') % {'type': self},
            )
            return message_dict.get(self, default)

    notification_type = models.CharField(
        max_length=3, choices=NotificationTypes, default=NotificationTypes.INFO
    )

    notification_source = models.CharField(
        max_length=1, choices=NotificationSource, default=NotificationSource.SYSTEM
    )

    message_type = models.CharField(
        max_length=32, choices=NotificationMessageType, default=NotificationMessageType.CUSTOM
    )

    message_data = models.JSONField(blank=True, default=dict)

    domain = models.ForeignKey(
        DomainModel,
        on_delete=models.SET_NULL,
        blank=True, null=True,
        related_name='notifications')

    certificate = models.ForeignKey(
        CertificateModel, on_delete=models.SET_NULL, blank=True, null=True, related_name='notifications'
    )

    device = models.ForeignKey(
        DeviceModel,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='notifications')

    issuing_ca = models.ForeignKey(
        IssuingCaModel,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='notifications')

    event = models.CharField(max_length=255, blank=True, null=True)

    message = models.ForeignKey(  # only for custom messages
        NotificationMessageModel, on_delete=models.CASCADE, null=True, related_name='notifications'
    )

    statuses = models.ManyToManyField(NotificationStatus, related_name='notifications')

    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created at'))

    def __str__(self) -> str:
        """Returns a human-readable string."""
        return f'{self.get_notification_type_display()} - {self.message.short_description[:20]}'

    @property
    def short_translated(self) -> Any:
        """Returns the translated short description."""
        if self.message_type == NotificationModel.NotificationMessageType.CUSTOM:
            return self.message.short_description
        try:
            message_string = NotificationModel.NotificationMessageType(self.message_type).get_message()
        except ValueError:
            return force_str(_('Unknown Notification message type.'))
        return message_string.short.format(**self.message_data)

    @property
    def long_translated(self) -> Any:
        """Returns the translated long description."""
        if self.message_type == NotificationModel.NotificationMessageType.CUSTOM:
            return self.message.long_description
        try:
            message_string = NotificationModel.NotificationMessageType(self.message_type).get_message()
        except ValueError:
            return _('Guess we messed up. Type of this notification is %(type)s') % {'type': self.message_type}
        return message_string.long.format(**self.message_data)
