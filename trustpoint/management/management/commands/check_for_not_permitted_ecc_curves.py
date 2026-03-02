"""Management command to check for not permitted ECC curves."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone
from management.models import NotificationModel, NotificationStatus, SecurityConfig
from pki.models import CertificateModel


class Command(BaseCommand):
    """Custom Django management command to check certificates for not permitted ECC curves."""

    help = 'Check certificates using not permitted ECC curves.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_for_not_permitted_ecc_curves()
        self.stdout.write(self.style.SUCCESS('Not permitted ECC curves check completed.'))

    def _check_for_not_permitted_ecc_curves(self) -> None:
        """Task to check if any certificates are using not permitted ECC curves."""
        config = SecurityConfig.objects.first()
        if config is None:
            return
        not_permitted_ecc_curves = config.not_permitted_ecc_curve_oids

        not_permitted_ecc_certificates = CertificateModel.objects.filter(spki_ec_curve_oid__in=not_permitted_ecc_curves)
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for cert in not_permitted_ecc_certificates:
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
