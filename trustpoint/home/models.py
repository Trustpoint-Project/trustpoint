"""Module that contains all models corresponding to the devices app."""

from __future__ import annotations

import logging

from devices.models import DeviceModel
from django.db import models
from django.utils.translation import gettext_lazy as _
from pki.models.certificate import CertificateModel

from pki.models.issuing_ca import IssuingCaModel
from pki.models.domain import DomainModel

log = logging.getLogger('tp.home')


class NotificationStatus(models.Model):
    """Model representing a status a notification can have."""

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
        return self.get_status_display()


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

    class NotificationTypes(models.TextChoices):
        """Supported Notification Types."""

        SETUP = 'SET', _('SETUP')
        # DEBUG = 'DEB', _('DEBUG')
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

        def get_message(self) -> str:
            """Returns the message for the given type."""
            message_dict = {
                self.CUSTOM: NotificationMessage(_('Custom Message')),
                # Test notifications, generated by create_notifications.py
                self.ISSUING_CA_TEST: NotificationMessage(
                    _('Test for Issuing CA: {ca}'), _('Notification for Issuing CA: {ca}')
                ),
                self.DOMAIN_TEST: NotificationMessage(
                    _('Test for Domain: {domain}'), _('Notification for Domain: {domain}')
                ),
                self.CERT_TEST: NotificationMessage(
                    _('Test for Certificate: {cn}'),
                    _('Notification for Certificate: Common Name {cn} with Serial Number {sn}'),
                ),
                self.DEVICE_TEST: NotificationMessage(
                    _('Test for Device: {device}'), _('Notification for Device: {device}')
                ),
                # Welcome notifications
                self.WELCOME_POPULATE_TEST_DATA: NotificationMessage(
                    _('Populate test data'),
                    _('Click <a href="{url}">here</a> to add test issuing CAs, domains and devices.'),
                ),
                self.TRUSTPOINT_DOCUMENTATION: NotificationMessage(
                    _('Access the Trustpoint Documentation'),
                    _('You can find the official Trustpoint documentation here: {link}'),
                ),
                self.TRUSTPOINT_PROJECT_INFO: NotificationMessage(
                    _('Explore the Trustpoint project'),
                    _(
                        'Visit the Trustpoint GitHub repository for more information: '
                        '<a href="{url_github}" target="_blank">Trustpoint GitHub</a><br>'
                        'Learn more about industrial security and the Trustpoint project on our '
                        '<a href="{url_homepage}" target="_blank">homepage</a>'
                    ),
                ),
                self.WELCOME_MESSAGE: NotificationMessage(
                    _('Welcome to Trustpoint!'),
                    _(
                        'Thank you for setting up Trustpoint. This system will help you manage your certificates and secure your environment.'
                    ),
                ),
                # Periodic task notifications
                self.SYSTEM_NOT_HEALTHY: NotificationMessage(
                    _('System health check failed'),
                    _(
                        'The system health check detected an issue with one or more services. Please investigate immediately.'
                    ),
                ),
                self.VULNERABILITY: NotificationMessage(
                    _('Security vulnerability detected'),
                    _(
                        'A security vulnerability affecting system components has been detected. Immediate attention required.'
                    ),
                ),
                self.CERT_EXPIRING: NotificationMessage(
                    _('Certificate {common_name} is expiring soon'),
                    _('The certificate {common_name} is set to expire on {not_valid_after}.'),
                ),
                self.CERT_EXPIRED: NotificationMessage(
                    _('Certificate {common_name} has expired'),
                    _('The certificate {common_name} expired on {not_valid_after}.'),
                ),
                self.ISSUING_CA_EXPIRING: NotificationMessage(
                    _('Issuing CA {unique_name} is expiring soon'),
                    _('The issuing CA {unique_name} is set to expire on {not_valid_after}.'),
                ),
                self.ISSUING_CA_EXPIRED: NotificationMessage(
                    _('Issuing CA {unique_name} has expired'),
                    _('The issuing CA {unique_name} expired on {not_valid_after}.'),
                ),
                self.DOMAIN_NO_ISSUING_CA: NotificationMessage(
                    _('Domain {unique_name} has no Issuing CA assigned'),
                    _('The domain {unique_name} currently has no Issuing CA assigned.'),
                ),
                self.DEVICE_NOT_ONBOARDED: NotificationMessage(
                    _('Device {device} is not onboarded in {domain}'),
                    _('The device {device} has not completed onboarding.'),
                ),
                self.DEVICE_ONBOARDING_FAILED: NotificationMessage(
                    _('Device {device} onboarding failed'), _('The device {device} failed onboarding.')
                ),
                self.DEVICE_CERT_REVOKED: NotificationMessage(
                    _('Device {device} certificate revoked'),
                    _('The device {device} has had its certificate revoked. The device may no longer be trusted.'),
                ),
                self.WEAK_SIGNATURE_ALGORITHM: NotificationMessage(
                    _('Certificate {common_name} uses a weak signature algorithm'),
                    _('The certificate {common_name} is signed using {signature_algorithm}, which is considered weak.'),
                ),
                self.INSUFFICIENT_KEY_LENGTH: NotificationMessage(
                    _('Certificate {common_name} uses insufficient key length'),
                    _(
                        'The certificate {common_name} uses an RSA key size of {spki_key_size} bits, which is less than the recommended 2048 bits.'
                    ),
                ),
                self.WEAK_ECC_CURVE: NotificationMessage(
                    _('Certificate {common_name} uses a weak ECC curve'),
                    _(
                        'The certificate {common_name} is using the {spki_ec_curve} ECC curve, which is no longer recommended.'
                    ),
                ),
            }

            default = NotificationMessage(
                _('Unknown Notification message string.'),
                _('Guess we messed up. Type of this notification is %(type)s') % {'type': self},
            )
            return message_dict.get(self, default)

    notification_type = models.CharField(
        max_length=3, choices=NotificationTypes.choices, default=NotificationTypes.INFO
    )

    notification_source = models.CharField(
        max_length=1, choices=NotificationSource.choices, default=NotificationSource.SYSTEM
    )

    message_type = models.CharField(
        max_length=32, choices=NotificationMessageType.choices, default=NotificationMessageType.CUSTOM
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
    def short_translated(self) -> str:
        """Returns the translated short description."""
        if self.message_type == NotificationModel.NotificationMessageType.CUSTOM:
            return self.message.short_description
        try:
            message_string = NotificationModel.NotificationMessageType(self.message_type).get_message()
        except ValueError:
            return _('Unknown Notification message type.')
        return message_string.short.format(**self.message_data)

    @property
    def long_translated(self) -> str:
        """Returns the translated long description."""
        if self.message_type == NotificationModel.NotificationMessageType.CUSTOM:
            return self.message.long_description
        try:
            message_string = NotificationModel.NotificationMessageType(self.message_type).get_message()
        except ValueError:
            return _('Guess we messed up. Type of this notification is %(type)s') % {'type': self.message_type}
        return message_string.long.format(**self.message_data)
