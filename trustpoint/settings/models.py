"""Models concerning the Trustpoint settings."""
from typing import ClassVar

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

    security_mode = models.CharField(max_length=6, choices=SecurityModeChoices.choices, default=SecurityModeChoices.LOW)

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

