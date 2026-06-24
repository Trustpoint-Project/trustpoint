"""Management command to check the validity of signing key certificates.

This module defines a Django management command that checks for expiring
or expired signing authority certificates. Expiring signing keys trigger
a WARNING notification, while expired signing keys trigger a CRITICAL
notification. Notifications are created only if they do not already exist
for the given signer and event.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from management.models import NotificationConfig, NotificationModel, NotificationStatus
from signer.models import SignerModel


class Command(BaseCommand):
    """Management command to check for expiring or expired signing key certificates.

    Expiring signing keys trigger a WARNING notification,
    while expired signing keys trigger a CRITICAL notification.
    """

    help = 'Check for expiring or expired signing key certificates.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_signer_key_validity()
        self.stdout.write(self.style.SUCCESS('Signing key validity check completed.'))

    def _check_signer_key_validity(self) -> None:
        """Check for signing keys whose certificates are expiring soon or have already expired.

        Uses the certificate expiry warning threshold from the notification configuration.
        """
        config = NotificationConfig.get()
        current_time = timezone.now()
        expiring_threshold = current_time + timedelta(days=config.cert_expiry_warning_days)

        self._new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for signer in SignerModel.objects.filter(is_active=True).select_related('credential'):
            cert_model = signer.credential.certificate_or_error
            not_valid_after = cert_model.not_valid_after

            if not_valid_after is None:
                continue

            if not_valid_after <= current_time:
                self._create_notification(
                    signer=signer,
                    event=f'SIGNER_KEY_EXPIRED_{signer.pk}',
                    notification_type=NotificationModel.NotificationTypes.CRITICAL,
                    message_type=NotificationModel.NotificationMessageType.SIGNER_KEY_EXPIRED,
                    not_valid_after=not_valid_after,
                )
            elif not_valid_after <= expiring_threshold:
                self._create_notification(
                    signer=signer,
                    event=f'SIGNER_KEY_EXPIRING_{signer.pk}',
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.SIGNER_KEY_EXPIRING,
                    not_valid_after=not_valid_after,
                )

    def _create_notification(
        self,
        signer: SignerModel,
        event: str,
        notification_type: NotificationModel.NotificationTypes,
        message_type: NotificationModel.NotificationMessageType,
        not_valid_after: Any,
    ) -> None:
        """Create a notification for a signing key.

        Skips notification creation if one already exists for the given event.

        Args:
            signer: The signer model instance.
            event: A unique event identifier for deduplication.
            notification_type: The notification severity level.
            message_type: The notification message type enum value.
            not_valid_after: The certificate expiry datetime.
        """
        if NotificationModel.objects.filter(event=event).exists():
            return

        message_data = {
            'signer_name': signer.unique_name,
            'not_valid_after': not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
        }

        notification = NotificationModel.objects.create(
            created_at=timezone.now(),
            notification_source=NotificationModel.NotificationSource.SYSTEM,
            notification_type=notification_type,
            message_type=message_type,
            event=event,
            message_data=message_data,
        )
        notification.statuses.add(self._new_status)
