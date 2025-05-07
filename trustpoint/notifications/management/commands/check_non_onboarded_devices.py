"""Management command to check for not onboarded devices."""

from __future__ import annotations

from typing import Any

from devices.models import DeviceModel
from django.core.management.base import BaseCommand
from django.utils import timezone
from notifications.models import NotificationModel, NotificationStatus

new_status, created = NotificationStatus.objects.get_or_create(status='NEW')


class Command(BaseCommand):
    """Management command to check for devices not onboarded.

    This command identifies devices that have not been onboarded (status: `NO_ONBOARDING`)
    and generates informational notifications for each device. If a notification for
    a specific device already exists, it will be skipped.
    """

    help = 'Check for devices not onboarded.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_non_onboarded_devices()
        self.stdout.write(self.style.SUCCESS('Non-onboarded devices check completed.'))

    def _check_non_onboarded_devices(self) -> None:
        """Task to create an info notification if a device is not onboarded."""
        non_onboarded_devices = DeviceModel.objects.filter(onboarding_status=DeviceModel.OnboardingStatus.PENDING)

        for device in non_onboarded_devices:
            if not NotificationModel.objects.filter(event='DEVICE_NOT_ONBOARDED', device=device).exists():
                message_data = {'device': device.common_name, 'domain': device.domain.unique_name}

                notification = NotificationModel.objects.create(
                    device=device,
                    created_at=timezone.now(),
                    notification_source=NotificationModel.NotificationSource.DEVICE,
                    notification_type=NotificationModel.NotificationTypes.INFO,
                    message_type=NotificationModel.NotificationMessageType.DEVICE_NOT_ONBOARDED,
                    event='DEVICE_NOT_ONBOARDED',
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
