"""Management command to check the validity of CRLs.

This module defines a Django management command that checks for expiring
or expired Certificate Revocation Lists (CRLs). Expiring CRLs trigger a
WARNING notification, while expired CRLs trigger a CRITICAL notification.
Notifications are created only if they do not already exist for the given
CRL and event.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, cast

from django.core.management.base import BaseCommand
from django.utils import timezone

from management.models import NotificationConfig, NotificationModel, NotificationStatus
from pki.models import CrlModel


class Command(BaseCommand):
    """Management command to check for expiring or expired CRLs.

    Expiring CRLs trigger a WARNING notification, while expired CRLs trigger a CRITICAL notification.
    """

    help = 'Check for expiring or expired CRLs.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_crl_validity()
        self.stdout.write(self.style.SUCCESS('CRL validity check completed.'))

    def _check_crl_validity(self) -> None:
        """Check for CRLs that are expiring soon or have already expired.

        Only active CRLs with a ``next_update`` value are checked.
        Expiring CRLs: Within the configured warning threshold.
        Expired CRLs: Already past their ``next_update`` date.
        """
        config = NotificationConfig.get()
        current_time = timezone.now()
        expiring_threshold = current_time + timedelta(days=config.crl_expiry_warning_days)

        active_crls = CrlModel.objects.filter(is_active=True, next_update__isnull=False).select_related('ca')

        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for crl in active_crls:
            next_update = crl.next_update
            if next_update is None:
                continue

            if next_update <= current_time:
                self._create_notification(
                    crl=crl,
                    event=f'CRL_EXPIRED_{crl.pk}',
                    notification_type=cast(
                        'NotificationModel.NotificationTypes', NotificationModel.NotificationTypes.CRITICAL
                    ),
                    message_type=cast(
                        'NotificationModel.NotificationMessageType',
                        NotificationModel.NotificationMessageType.CRL_EXPIRED,
                    ),
                    new_status=new_status,
                )
            elif next_update <= expiring_threshold:
                self._create_notification(
                    crl=crl,
                    event=f'CRL_EXPIRING_{crl.pk}',
                    notification_type=cast(
                        'NotificationModel.NotificationTypes', NotificationModel.NotificationTypes.WARNING
                    ),
                    message_type=cast(
                        'NotificationModel.NotificationMessageType',
                        NotificationModel.NotificationMessageType.CRL_EXPIRING,
                    ),
                    new_status=new_status,
                )

    def _create_notification(
        self,
        crl: CrlModel,
        event: str,
        notification_type: str | NotificationModel.NotificationTypes,
        message_type: str | NotificationModel.NotificationMessageType,
        new_status: NotificationStatus,
    ) -> None:
        """Create a notification for a CRL.

        Skips notification creation if one already exists for the given event.

        Args:
            crl: The CRL model instance.
            event: A unique event identifier for deduplication.
            notification_type: The notification severity level.
            message_type: The notification message type enum value.
            new_status: The NEW status instance to attach.
        """
        if NotificationModel.objects.filter(event=event).exists():
            return

        ca_name = crl.ca.unique_name if crl.ca else 'Unknown CA'
        next_update_str = crl.next_update.strftime('%Y-%m-%d %H:%M:%S') if crl.next_update else 'N/A'

        message_data = {
            'ca_name': ca_name,
            'next_update': next_update_str,
        }

        notification = NotificationModel.objects.create(
            issuing_ca=crl.ca,
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.ISSUING_CA,
            notification_type=notification_type,
            message_type=message_type,
            event=event,
            message_data=message_data,
        )
        notification.statuses.add(new_status)
