"""Management command to check for initializing the notifications configuration."""
from typing import Any

from django.core.management.base import BaseCommand
from notifications.models import (
    NotificationConfig,
    WeakECCCurve,
    WeakSignatureAlgorithm,
)


class Command(BaseCommand):
    """Management command to initialize NotificationConfig with default weak ECC curves and signature algorithms."""

    help = 'Initializes default NotificationConfig with known weak ECC curves and signature algorithms.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Create or update NotificationConfig with default weak ECC curves and signature algorithms."""
        # Create or get ECC curve entries
        ecc_oids = {
            '1.2.840.10045.3.1.1': 'SECP192R1',
            '1.3.132.0.8': 'SECP160R1',
            '1.3.132.0.33': 'SECP224R1',
        }

        ecc_instances = []
        for oid, label in ecc_oids.items():
            ecc, created = WeakECCCurve.objects.get_or_create(oid=oid)
            ecc_instances.append(ecc)
            self.stdout.write(f"{'Created' if created else 'Found'} ECC curve: {label} ({oid})")

        # Create or get Signature algorithm entries
        sig_oids = {
            '1.2.840.113549.2.5': 'MD5',
            '1.3.14.3.2.26': 'SHA-1',
            '2.16.840.1.101.3.4.2.4': 'SHA-224',
        }

        sig_instances = []
        for oid, label in sig_oids.items():
            sig, created = WeakSignatureAlgorithm.objects.get_or_create(oid=oid)
            sig_instances.append(sig)
            self.stdout.write(f"{'Created' if created else 'Found'} Signature algorithm: {label} ({oid})")

        # Set them in the NotificationConfig
        config, created = NotificationConfig.objects.get_or_create()
        config.weak_ecc_curves.set(ecc_instances)
        config.weak_signature_algorithms.set(sig_instances)
        config.save()

        self.stdout.write(self.style.SUCCESS('Notification configuration initialized successfully.'))
