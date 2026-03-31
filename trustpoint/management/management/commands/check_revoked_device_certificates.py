"""Management command to check for devices with revoked certificates."""

from __future__ import annotations

from typing import Any, cast

from devices.models import DeviceModel
from django.core.management.base import BaseCommand
from django.utils import timezone
from management.models import NotificationModel, NotificationStatus
from pki.models import IssuedCredentialModel

new_status, created = NotificationStatus.objects.get_or_create(status='NEW')


class Command(BaseCommand):
    """Management command to check for devices with revoked certificates.

    This command identifies devices that have issued credentials with revoked
    certificates and generates warning notifications for each device.
    If a notification for a specific device already exists, it will be skipped.
    """

    help = 'Check for devices with revoked certificates.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_revoked_device_certificates()
        self.stdout.write(self.style.SUCCESS('Revoked device certificates check completed.'))

    def _check_revoked_device_certificates(self) -> None:
        """Task to create a warning notification if a device has a revoked certificate."""
        # Find devices that have at least one revoked certificate
        devices_with_revoked_certs = DeviceModel.objects.filter(
            issued_credentials__credential__certificate__revoked_certificate__isnull=False,
        ).distinct()

        for device in devices_with_revoked_certs:
            event = f'DEVICE_CERT_REVOKED_{device.pk}'
            if not NotificationModel.objects.filter(event=event, device=device).exists():
                device_name = cast('DeviceModel', device).common_name

                message_data = {'device': device_name}

                notification = NotificationModel.objects.create(
                    device=device,
                    created_at=timezone.now(),
                    notification_source=NotificationModel.NotificationSource.DEVICE,
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.DEVICE_CERT_REVOKED,
                    event=event,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
