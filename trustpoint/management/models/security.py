"""Security Configuration Model."""
from __future__ import annotations

from typing import Any, ClassVar

from django.db import models
from django.utils.translation import gettext_lazy as _

from management.models import NotificationConfig, WeakECCCurve, WeakSignatureAlgorithm
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

    NOTIFICATION_CONFIGURATIONS: ClassVar[dict[str, dict[str, Any]]] = {
        SecurityModeChoices.DEV: {

            'rsa_minimum_key_size': 1024,
            'weak_ecc_curves': [],
            'weak_signature_algorithms': [],
        },
        SecurityModeChoices.LOW: {
            'rsa_minimum_key_size': 1024,
            'weak_ecc_curves': [],
            'weak_signature_algorithms': [],
        },
        SecurityModeChoices.MEDIUM: {
            'rsa_minimum_key_size': 2048,
            'weak_ecc_curves': [
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
            ],
        },
        SecurityModeChoices.HIGH: {
            'rsa_minimum_key_size': 3072,
            'weak_ecc_curves': [
            ],
            'weak_signature_algorithms': [
                WeakSignatureAlgorithm.SignatureChoices.MD5,
                WeakSignatureAlgorithm.SignatureChoices.SHA1,
                WeakSignatureAlgorithm.SignatureChoices.SHA224,
            ],
        },
        SecurityModeChoices.HIGHEST: {
            'rsa_minimum_key_size': 4096,
            'weak_ecc_curves': [
                WeakECCCurve.ECCCurveChoices.SECP160R1,
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

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.security_mode}'

    def apply_security_settings(self) -> None:
        """Apply appropriate configuration values based on the security mode."""
        if self.security_mode:
            notification_config = NotificationConfig.get()

            config_values = self.NOTIFICATION_CONFIGURATIONS.get(self.security_mode, {})

            notification_config.rsa_minimum_key_size = config_values.get(
                'rsa_minimum_key_size', notification_config.rsa_minimum_key_size
            )

            weak_ecc_curve_oids = config_values.get('weak_ecc_curves', [])
            weak_signature_algorithm_oids = config_values.get('weak_signature_algorithms', [])

            weak_ecc_curves = WeakECCCurve.objects.filter(oid__in=weak_ecc_curve_oids)
            weak_signature_algorithms = WeakSignatureAlgorithm.objects.filter(oid__in=weak_signature_algorithm_oids)

            notification_config.weak_ecc_curves.set(weak_ecc_curves)
            notification_config.weak_signature_algorithms.set(weak_signature_algorithms)

            notification_config.save()
