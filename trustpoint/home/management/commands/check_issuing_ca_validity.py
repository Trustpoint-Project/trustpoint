"""Management command to check the validity of Issuing CAs."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, cast

from django.core.management.base import BaseCommand
from django.utils import timezone
from home.models import NotificationModel, NotificationStatus
from pki.models import IssuingCaModel


class Command(BaseCommand):
    """A Django management command to check for expiring or expired issuing CAs.

    This command identifies Issuing Certificate Authorities (CAs) with certificates
    that are either expiring or expired and generates appropriate notifications for
    them in the system.
    """

    help = 'Check for expiring or expired issuing CAs.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command."""
        self._check_issuing_ca_validity()
        self.stdout.write(self.style.SUCCESS('Issuing CA validity check completed.'))

    def _check_issuing_ca_validity(self) -> None:
        """Task to check for both expiring and expired Issuing CAs.

        Expiring CAs trigger a WARNING notification, while expired CAs trigger a CRITICAL notification.
        """
        expiring_threshold = timezone.now() + timedelta(days=30)
        current_time = timezone.now()

        expiring_cas = IssuingCaModel.objects.filter(
            credential__certificate__not_valid_after__lte=expiring_threshold,
            credential__certificate__not_valid_after__gt=current_time,
        )

        expired_cas = IssuingCaModel.objects.filter(credential__certificate__not_valid_after__lte=current_time)

        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        # Handle expiring Issuing CAs
        for ca in expiring_cas:
            self._create_notification(
                issuing_ca=ca,
                event='ISSUING_CA_EXPIRING',
                notification_type=cast(
                    NotificationModel.NotificationTypes, NotificationModel.NotificationTypes.WARNING
                ),
                message_type=cast(
                    NotificationModel.NotificationMessageType, NotificationModel.NotificationMessageType.CERT_EXPIRING
                ),
                new_status=new_status,
            )

        # Handle expired Issuing CAs
        for ca in expired_cas:
            self._create_notification(
                issuing_ca=ca,
                event='ISSUING_CA_EXPIRED',
                notification_type=cast(
                    NotificationModel.NotificationTypes, NotificationModel.NotificationTypes.CRITICAL
                ),
                message_type=cast(
                    NotificationModel.NotificationMessageType, NotificationModel.NotificationMessageType.CERT_EXPIRED
                ),
                new_status=new_status,
            )

    def _create_notification(
        self,
        issuing_ca: IssuingCaModel,
        event: str,
        notification_type: str | NotificationModel.NotificationTypes,
        message_type: str | NotificationModel.NotificationMessageType,
        new_status: NotificationStatus,
    ) -> None:
        """Helper function to create a notification for an Issuing CA.

        Skips notification creation if one already exists for the given event and Issuing CA.
        """
        if not NotificationModel.objects.filter(event=event, issuing_ca=issuing_ca).exists():
            message_data = {
                'unique_name': issuing_ca.unique_name,
                'not_valid_after': issuing_ca.credential.get_certificate().not_valid_after,
            }
            notification = NotificationModel.objects.create(
                issuing_ca=issuing_ca,
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                notification_type=notification_type,
                message_type=message_type,
                event=event,
                message_data=message_data,
            )
            notification.statuses.add(new_status)
