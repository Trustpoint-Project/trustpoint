"""Management command to check for devices with failed onboarding attempts."""

from __future__ import annotations

from typing import Any, cast

from devices.models import DeviceModel
from django.core.management.base import BaseCommand
from django.utils import timezone
from management.models import NotificationModel, NotificationStatus
from workflows.models import EnrollmentRequest, State

new_status, created = NotificationStatus.objects.get_or_create(status='NEW')


class Command(BaseCommand):
    """Management command to check for devices with failed onboarding.

    This command identifies devices that have enrollment requests in a
    FAILED or REJECTED state and generates warning notifications for each device.
    If a notification for a specific device already exists, it will be skipped.
    """

    help = 'Check for devices with failed onboarding attempts.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_onboarding_failed_devices()
        self.stdout.write(self.style.SUCCESS('Onboarding failed devices check completed.'))

    def _check_onboarding_failed_devices(self) -> None:
        """Task to create a warning notification if a device has a failed onboarding attempt."""
        failed_enrollment_requests = EnrollmentRequest.objects.filter(
            aggregated_state__in=[State.FAILED, State.REJECTED],
            device__isnull=False,
        ).select_related('device')

        for enrollment_request in failed_enrollment_requests:
            device = enrollment_request.device
            if device is None:
                continue

            event = f'DEVICE_ONBOARDING_FAILED_{device.pk}_{enrollment_request.pk}'
            if not NotificationModel.objects.filter(event=event, device=device).exists():
                device_name = cast('DeviceModel', device).common_name

                message_data = {'device': device_name}

                notification = NotificationModel.objects.create(
                    device=device,
                    created_at=timezone.now(),
                    notification_source=NotificationModel.NotificationSource.DEVICE,
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.DEVICE_ONBOARDING_FAILED,
                    event=event,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
