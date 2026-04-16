"""Management command to check the validity of the Trustpoint TLS server certificate.

This module defines a Django management command that checks whether the active
Trustpoint TLS server certificate is expiring soon or has already expired.
Expiring certificates trigger a WARNING notification, while expired certificates
trigger a CRITICAL notification.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from management.models import NotificationConfig, NotificationModel, NotificationStatus
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel


class Command(BaseCommand):
    """Management command to check the Trustpoint TLS server certificate validity.

    Creates a WARNING notification if the certificate is expiring within the
    configured threshold, or a CRITICAL notification if it has already expired.
    """

    help = 'Check the validity of the active Trustpoint TLS server certificate.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_tls_certificate_validity()
        self.stdout.write(self.style.SUCCESS('TLS server certificate validity check completed.'))

    def _check_tls_certificate_validity(self) -> None:
        """Check the active Trustpoint TLS server certificate for expiry.

        Uses the certificate expiry warning threshold from the notification configuration.
        """
        try:
            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.select_related(
                'credential__certificate',
            ).get(id=1)
        except ActiveTrustpointTlsServerCredentialModel.DoesNotExist:
            self.stdout.write(self.style.WARNING('No active TLS server credential configured.'))
            return

        credential = active_tls.credential
        if credential is None:
            self.stdout.write(self.style.WARNING('Active TLS credential has no linked credential.'))
            return

        certificate = credential.certificate
        if certificate is None:
            self.stdout.write(self.style.WARNING('Active TLS credential has no linked certificate.'))
            return

        not_valid_after = certificate.not_valid_after
        if not_valid_after is None:
            return

        config = NotificationConfig.get()
        current_time = timezone.now()
        expiring_threshold = current_time + timedelta(days=config.cert_expiry_warning_days)

        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        if not_valid_after <= current_time:
            self._create_notification(
                event='TLS_CERT_EXPIRED',
                notification_type=NotificationModel.NotificationTypes.CRITICAL,
                message_type=NotificationModel.NotificationMessageType.TLS_CERT_EXPIRED,
                not_valid_after=not_valid_after,
                new_status=new_status,
            )
        elif not_valid_after <= expiring_threshold:
            self._create_notification(
                event='TLS_CERT_EXPIRING',
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.TLS_CERT_EXPIRING,
                not_valid_after=not_valid_after,
                new_status=new_status,
            )

    @staticmethod
    def _create_notification(
        event: str,
        notification_type: NotificationModel.NotificationTypes,
        message_type: NotificationModel.NotificationMessageType,
        not_valid_after: Any,
        new_status: NotificationStatus,
    ) -> None:
        """Create a notification for the TLS server certificate.

        Skips notification creation if one already exists for the given event.

        Args:
            event: A unique event identifier for deduplication.
            notification_type: The notification severity level.
            message_type: The notification message type enum value.
            not_valid_after: The certificate expiry datetime.
            new_status: The NEW status instance to attach.
        """
        if NotificationModel.objects.filter(event=event).exists():
            return

        message_data = {
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
        notification.statuses.add(new_status)
