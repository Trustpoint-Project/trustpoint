"""Management command to check for weak ECC curves."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone
from home.models import NotificationModel, NotificationStatus
from pki.models import CertificateModel


class Command(BaseCommand):
    """Custom Django management command to check certificates for deprecated or weak ECC curves."""

    help = 'Check certificates using weak or deprecated ECC curves.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command."""
        self._check_for_weak_ecc_curves()
        self.stdout.write(self.style.SUCCESS('Weak ECC curves check completed.'))

    def _check_for_weak_ecc_curves(self) -> None:
        """Task to check if any certificates are using deprecated or weak ECC curves."""
        weak_ecc_curves = ['1.2.840.10045.3.1.1', '1.3.132.0.33']  # OIDs for weak ECC curves like SECP192R1

        weak_ecc_certificates = CertificateModel.objects.filter(spki_ec_curve_oid__in=weak_ecc_curves)
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for cert in weak_ecc_certificates:
            if not NotificationModel.objects.filter(event='WEAK_ECC_CURVE', certificate=cert).exists():
                message_data = {'common_name': cert.common_name, 'spki_ec_curve': cert.spki_ec_curve}

                notification = NotificationModel.objects.create(
                    certificate=cert,
                    created_at=timezone.now(),
                    event='WEAK_ECC_CURVE',
                    notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.WEAK_ECC_CURVE,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
