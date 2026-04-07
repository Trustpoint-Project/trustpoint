"""Management command to check for failed OPC UA GDS Push operations.

This module defines a Django management command that checks for OPC UA GDS Push
devices where the last scheduled update has failed or was never completed.
Failed pushes trigger a WARNING notification.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from devices.models import DeviceModel
from management.models import NotificationModel, NotificationStatus


class Command(BaseCommand):
    """Management command to check for failed OPC UA GDS Push operations.

    Identifies OPC UA GDS Push devices with periodic updates enabled where
    the scheduled update time has passed without being rescheduled, indicating
    a likely push failure.
    """

    help = 'Check for failed OPC UA GDS Push operations.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_gds_push_failures()
        self.stdout.write(self.style.SUCCESS('OPC UA GDS Push failure check completed.'))

    def _check_gds_push_failures(self) -> None:
        """Check for OPC UA GDS Push devices with overdue scheduled updates.

        A device is considered to have a failed push if:
        - It is an OPC UA GDS Push device
        - Periodic updates are enabled
        - The last scheduled update time is in the past (overdue)
        """
        current_time = timezone.now()

        overdue_devices = DeviceModel.objects.filter(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS_PUSH,
            opc_gds_push_enable_periodic_update=True,
            opc_gds_push_last_update_scheduled_at__isnull=False,
            opc_gds_push_last_update_scheduled_at__lt=current_time,
        )

        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for device in overdue_devices:
            scheduled_at = device.opc_gds_push_last_update_scheduled_at
            if scheduled_at is None:
                continue

            event = f'GDS_PUSH_FAILED_{device.pk}'
            if NotificationModel.objects.filter(event=event).exists():
                continue

            message_data = {
                'device': device.common_name,
                'error_message': (
                    f'Scheduled update at {scheduled_at.strftime("%Y-%m-%d %H:%M:%S")} '
                    f'was not completed. The device may be unreachable.'
                ),
            }

            notification = NotificationModel.objects.create(
                device=device,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.DEVICE,
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.GDS_PUSH_FAILED,
                event=event,
                message_data=message_data,
            )
            notification.statuses.add(new_status)
