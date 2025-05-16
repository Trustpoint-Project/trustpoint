"""Management command to check certificates with insufficient key lengths."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone
from notifications.models import NotificationModel, NotificationStatus, NotificationConfig
from pki.models import CertificateModel


class Command(BaseCommand):
    """Command to check for certificates using insufficient RSA key lengths."""

    help = 'Check certificates with insufficient key lengths.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_for_insufficient_key_length()
        self.stdout.write(self.style.SUCCESS('Insufficient key length check completed.'))

    def _check_for_insufficient_key_length(self) -> None:
        """Task to check if any certificates are using insufficient key lengths."""
        config = NotificationConfig.get()

        rsa_minimum_key_size = config.rsa_minimum_key_size
        insufficient_key_certificates = CertificateModel.objects.filter(
            spki_algorithm_oid='1.2.840.113549.1.1.1',
            spki_key_size__lt=rsa_minimum_key_size,
        )
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for cert in insufficient_key_certificates:
            if not NotificationModel.objects.filter(event='INSUFFICIENT_KEY_LENGTH', certificate=cert).exists():
                message_data = {'common_name': cert.common_name, 'spki_key_size': cert.spki_key_size}

                notification = NotificationModel.objects.create(
                    certificate=cert,
                    created_at=timezone.now(),
                    event='INSUFFICIENT_KEY_LENGTH',
                    notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.INSUFFICIENT_KEY_LENGTH,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
