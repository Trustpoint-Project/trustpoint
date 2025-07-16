"""Models concerning the Trustpoint settings."""
from typing import ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from notifications.models import WeakECCCurve, WeakSignatureAlgorithm
from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityConfig(models.Model):
    """Security Configuration model."""

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes."""

        DEV = '0', _('Testing env')
        LOW = '1', _('Basic')
        MEDIUM = '2', _('Medium')
        HIGH = '3', _('High')
        HIGHEST = '4', _('Highest')

    security_mode = models.CharField(max_length=6, choices=SecurityModeChoices, default=SecurityModeChoices.LOW)

    auto_gen_pki = models.BooleanField(default=False)
    auto_gen_pki_key_algorithm = models.CharField(
        max_length=24, choices=AutoGenPkiKeyAlgorithm, default=AutoGenPkiKeyAlgorithm.RSA2048
    )

    NOTIFICATION_CONFIGURATIONS: ClassVar[dict] = {
        SecurityModeChoices.DEV: {
            'cert_expiry_warning_days': 10,
            'issuing_ca_expiry_warning_days': 10,
            'rsa_minimum_key_size': 1024,
            'weak_ecc_curves': [],
            'weak_signature_algorithms': [],
        },
        SecurityModeChoices.LOW: {
            'cert_expiry_warning_days': 15,
            'issuing_ca_expiry_warning_days': 15,
            'rsa_minimum_key_size': 1024,
            'weak_ecc_curves': [],
            'weak_signature_algorithms': [],
        },
        SecurityModeChoices.MEDIUM: {
            'cert_expiry_warning_days': 20,
            'issuing_ca_expiry_warning_days': 20,
            'rsa_minimum_key_size': 2048,
            'weak_ecc_curves': [
                WeakECCCurve.ECCCurveChoices.SECP160R1,
                WeakECCCurve.ECCCurveChoices.SECT163K1,
                WeakECCCurve.ECCCurveChoices.SECT163R2,
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
            ],
        },
        SecurityModeChoices.HIGH: {
            'cert_expiry_warning_days': 25,
            'issuing_ca_expiry_warning_days': 25,
            'rsa_minimum_key_size': 3072,
            'weak_ecc_curves': [
                WeakECCCurve.ECCCurveChoices.SECP160R1,
                WeakECCCurve.ECCCurveChoices.SECT163K1,
                WeakECCCurve.ECCCurveChoices.SECT163R2,
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
                WeakSignatureAlgorithm.SignatureChoices.SHA224,
            ],
        },
        SecurityModeChoices.HIGHEST: {
            'cert_expiry_warning_days': 30,
            'issuing_ca_expiry_warning_days': 30,
            'rsa_minimum_key_size': 4096,
            'weak_ecc_curves': [
                WeakECCCurve.ECCCurveChoices.SECP160R1,
                WeakECCCurve.ECCCurveChoices.SECT163K1,
                WeakECCCurve.ECCCurveChoices.SECT163R2,
                WeakECCCurve.ECCCurveChoices.SECP192R1,
                WeakECCCurve.ECCCurveChoices.SECP224R1,
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
                WeakSignatureAlgorithm.SignatureChoices.SHA224,
            ],
        },
    }

    notification_config = models.OneToOneField(
        'notifications.NotificationConfig',
        on_delete=models.CASCADE,
        related_name='security_config',
        null=True,
        blank=False,
        help_text=_('Notification configuration associated with this security level.'),
    )

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.security_mode}'
    
    def apply_security_settings(self) -> None:
        """Apply appropriate configuration values based on the security mode."""
        if self.security_mode and self.notification_config:
            # Get the default configuration for the selected security level
            config_values = self.NOTIFICATION_CONFIGURATIONS.get(self.security_mode, {})

            # Apply values to the NotificationConfig
            self.notification_config.cert_expiry_warning_days = config_values.get(
                'cert_expiry_warning_days', self.notification_config.cert_expiry_warning_days
            )
            self.notification_config.issuing_ca_expiry_warning_days = config_values.get(
                'issuing_ca_expiry_warning_days', self.notification_config.issuing_ca_expiry_warning_days
            )
            self.notification_config.rsa_minimum_key_size = config_values.get(
                'rsa_minimum_key_size', self.notification_config.rsa_minimum_key_size
            )

            # Update WeakECCCurve and WeakSignatureAlgorithm relationships
            weak_ecc_curve_oids = config_values.get('weak_ecc_curves', [])
            weak_signature_algorithm_oids = config_values.get('weak_signature_algorithms', [])

            weak_ecc_curves = WeakECCCurve.objects.filter(oid__in=weak_ecc_curve_oids)
            weak_signature_algorithms = WeakSignatureAlgorithm.objects.filter(oid__in=weak_signature_algorithm_oids)

            self.notification_config.weak_ecc_curves.set(weak_ecc_curves)
            self.notification_config.weak_signature_algorithms.set(weak_signature_algorithms)

            self.notification_config.save()


class TlsSettings(models.Model):
    """TLS settings model"""

    ipv4_address = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)

    @classmethod
    def get_first_ipv4_address(cls) -> str:
        """Get the first IPv4 address or a default value."""

        try:
            network_settings = cls.objects.get(id=1)
            ipv4_address = network_settings.ipv4_address
        except cls.DoesNotExist:
            ipv4_address = '127.0.0.1'

        return ipv4_address


class AppVersion(models.Model):
    objects: models.Manager['AppVersion']

    version = models.CharField(max_length=17)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'App Version'

    def __str__(self) -> str:
        return f'{self.version} @ {self.last_updated.isoformat()}'


class BackupOptions(models.Model):
    """A singleton model (we always operate with pk=1) for backup settings.
    We store host/port/user/local_storage, plus either a password or an SSH key.
    """

    class AuthMethod(models.TextChoices):
        PASSWORD = 'password', 'Password'
        SSH_KEY   = 'ssh_key',  'SSH Key'

    local_storage = models.BooleanField(default=True, verbose_name=_('Use local storage'))

    sftp_storage = models.BooleanField(default=False, verbose_name=_('Use SFTP storage'))

    host = models.CharField(max_length=255, verbose_name=_('Host'), blank=True)
    port = models.PositiveIntegerField(default=2222, verbose_name=_('Port'), blank=True)
    user = models.CharField(max_length=128, verbose_name=_('Username'), blank=True)

    auth_method = models.CharField(
        max_length=10,
        choices=AuthMethod.choices,
        default=AuthMethod.PASSWORD,
        verbose_name=_('Authentication Method')
    )

    # TODO (Dome): Storing passwords in plain text
    password = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Password'),
        help_text=_('Plain‐text password for SFTP.')
    )

    private_key = models.TextField(
        blank=True,
        verbose_name=_('SSH Private Key (PEM format)'),
        help_text=_('Paste the private key here (PEM).')
    )

    key_passphrase = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_('Key Passphrase'),
        help_text=_('Passphrase for the private key, if any.')
    )

    remote_directory = models.CharField(
        max_length=512,
        blank=True,
        default='/upload/trustpoint/',
        verbose_name=_('Remote Directory'),
        help_text=_('Remote directory (e.g. /backups/) where files should be uploaded. '
                  'Trailing slash is optional.'),
    )

    def clean(self):
        """Prevent the creation of more than one instance."""
        if not self.pk and BackupOptions.objects.exists():
            raise ValidationError(_('Only one instance of BackupOptions is allowed.'))

        if not self.sftp_storage:
            missing_fields = []
            if not self.host:
                missing_fields.append(_('Host'))
            if not self.user:
                missing_fields.append(_('Username'))
            if not self.auth_method:
                missing_fields.append(_('Authentication Method'))

            if missing_fields:
                raise ValidationError(
                    _('The following fields are required when SFTP storage is enabled: %(fields)s.'),
                    params={'fields': ', '.join(missing_fields)},
                )

        return super().clean()

    def save(self, *args, **kwargs):
        """Ensure only one instance exists (singleton pattern)."""
        self.pk = 1
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f'{self.user}@{self.host}:{self.port} ({self.auth_method})'
