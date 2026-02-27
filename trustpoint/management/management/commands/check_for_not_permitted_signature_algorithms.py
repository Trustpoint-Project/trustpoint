"""Management command to check for not permitted signature algorithms."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone
from management.models import NotificationModel, NotificationStatus, SecurityConfig
from pki.models import CertificateModel


class Command(BaseCommand):
    """Custom Django management command to check certificates for not permitted signature algorithms."""

    help = 'Check certificates with not permitted signature algorithms.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_for_not_permitted_signature_algorithms()
        self.stdout.write(self.style.SUCCESS('Not permitted signature algorithms check completed.'))

    def _check_for_not_permitted_signature_algorithms(self) -> None:
        """Task to check if any certificates are using not permitted signature algorithms."""
        config = SecurityConfig.objects.first()
        if config is None:
            return
        not_permitted_algorithms = config.not_permitted_signature_algorithm_oids

        not_permitted_certificates = CertificateModel.objects.filter(signature_algorithm_oid__in=not_permitted_algorithms)
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for cert in not_permitted_certificates:
            if not NotificationModel.objects.filter(event='WEAK_SIGNATURE_ALGORITHM', certificate=cert).exists():
                message_data = {'common_name': cert.common_name, 'signature_algorithm': cert.signature_algorithm}

                notification = NotificationModel.objects.create(
                    certificate=cert,
                    created_at=timezone.now(),
                    event='WEAK_SIGNATURE_ALGORITHM',
                    notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.WEAK_SIGNATURE_ALGORITHM,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
