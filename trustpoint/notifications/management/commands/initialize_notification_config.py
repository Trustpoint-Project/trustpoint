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
        self.stdout.write("Seeding weak ECC curves...")
        ecc_instances = []
        for oid, label in WeakECCCurve.ECCCurveChoices.choices:
            ecc, created = WeakECCCurve.objects.get_or_create(oid=oid)
            ecc_instances.append(ecc)
            self.stdout.write(f"{'Created' if created else 'Found'} ECC curve: {label} ({oid})")

        self.stdout.write("Seeding weak signature algorithms...")
        sig_instances = []
        for oid, label in WeakSignatureAlgorithm.SignatureChoices.choices:
            sig, created = WeakSignatureAlgorithm.objects.get_or_create(oid=oid)
            sig_instances.append(sig)
            self.stdout.write(f"{'Created' if created else 'Found'} Signature algorithm: {label} ({oid})")

        # Set them in the NotificationConfig
        config, created = NotificationConfig.objects.get_or_create()
        config.weak_ecc_curves.set(ecc_instances)
        config.weak_signature_algorithms.set(sig_instances)
        config.save()

        self.stdout.write(self.style.SUCCESS('Notification configuration initialized successfully.'))
