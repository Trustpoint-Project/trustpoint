# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to check the validity of certificates.

This module defines a Django management command that checks for expiring
or expired certificates stored in the database. Expiring certificates
trigger a WARNING notification, while expired certificates trigger a
CRITICAL notification. Notifications are created only if they do not
already exist for the given certificate and event.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from management.models import NotificationConfig, NotificationModel, NotificationStatus
from pki.models import CertificateModel, IssuedCredentialModel


class Command(BaseCommand):
    """Management command to check for expiring or expired certificates.

    Expiring certificates trigger a WARNING notification, while expired certificates trigger a CRITICAL notification.
    """

    help = 'Check for expiring or expired certificates.'

    _existing_notifications: set[tuple[str, int, int | None]]
    _domains_by_certificate: dict[int, int]

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.Args.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_certificate_validity()
        self.stdout.write(self.style.SUCCESS('Certificate validity check completed.'))

    def _check_certificate_validity(self) -> None:
        """Check for certificates that are expiring soon or have already expired.

        Expiring certificates: Within the configured certificate warning period.
        Expired certificates: Already past their `not_valid_after` date.
        """
        config = NotificationConfig.get()
        current_time = timezone.now()
        expiring_threshold = current_time + timedelta(days=config.cert_expiry_warning_days)

        # Device certificates have their own revocation and CA/TLS checks.
        managed_device_certificates = CertificateModel.objects.filter(revoked_certificate__isnull=True).exclude(
            Q(credential__issuing_ca__isnull=False)
            | Q(credential__activetrustpointtlsservercredentialmodel__isnull=False)
        )
        expiring_certificates = managed_device_certificates.filter(
            not_valid_after__lte=expiring_threshold, not_valid_after__gt=current_time
        )
        expired_certificates = managed_device_certificates.filter(not_valid_after__lte=current_time)
        expiring_certificates = expiring_certificates.select_related('user_client_certificate__user')
        expired_certificates = expired_certificates.select_related('user_client_certificate__user')

        self._solve_revoked_certificate_alerts()
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        self._existing_notifications = set(
            NotificationModel.objects.filter(
                event__in=('CERTIFICATE_EXPIRING', 'CERTIFICATE_EXPIRED'),
                certificate__isnull=False,
            ).values_list('event', 'certificate_id', 'domain_id')
        )
        self._domains_by_certificate = dict(
            IssuedCredentialModel.objects.filter(
                credential__certificate__isnull=False,
                domain__isnull=False,
            ).values_list('credential__certificate_id', 'domain_id')
        )

        # Handle expiring certificates
        for cert in expiring_certificates:
            self._create_notification(
                certificate=cert,
                event='CERTIFICATE_EXPIRING',
                notification_type=NotificationModel.NotificationTypes.WARNING,
                message_type=NotificationModel.NotificationMessageType.CERT_EXPIRING,
                new_status=new_status,
            )

        # Handle expired certificates
        for cert in expired_certificates:
            self._create_notification(
                certificate=cert,
                event='CERTIFICATE_EXPIRED',
                notification_type=NotificationModel.NotificationTypes.CRITICAL,
                message_type=NotificationModel.NotificationMessageType.CERT_EXPIRED,
                new_status=new_status,
            )

    @staticmethod
    def _add_solved_status(notifications: Any) -> None:
        """Replace the open status with SOLVED without creating duplicate rows."""
        solved, _ = NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.SOLVED)
        new_status = NotificationStatus.StatusChoices.NEW
        for notification in notifications:
            notification.statuses.remove(*notification.statuses.filter(status=new_status))
            notification.statuses.add(solved)

    def _solve_revoked_certificate_alerts(self) -> None:
        """Close expiry alerts for certificates that are now revoked."""
        notifications = NotificationModel.objects.filter(
            event__in=('CERTIFICATE_EXPIRING', 'CERTIFICATE_EXPIRED'),
            certificate__revoked_certificate__isnull=False,
        ).exclude(statuses__status=NotificationStatus.StatusChoices.SOLVED)
        self._add_solved_status(notifications)

    def _solve_expiring_alert(self, certificate: CertificateModel, domain_id: int | None) -> None:
        """Close the warning that is superseded by the expired alert."""
        notifications = NotificationModel.objects.filter(
            event='CERTIFICATE_EXPIRING',
            certificate=certificate,
            domain_id=domain_id,
        ).exclude(statuses__status=NotificationStatus.StatusChoices.SOLVED)
        self._add_solved_status(notifications)

    def _create_notification(
        self,
        certificate: CertificateModel,
        event: str,
        notification_type: str | NotificationModel.NotificationTypes,
        message_type: str | NotificationModel.NotificationMessageType,
        new_status: NotificationStatus,
    ) -> None:
        """Helper function to create a notification for a certificate.

        Skips notification creation if one already exists for the given event and certificate.
        If the certificate is associated with a domain through an issued credential, creates
        a domain-associated notification. Otherwise, creates a standalone notification.
        """
        message_data = {
            'common_name': certificate.common_name,
            'not_valid_after': certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
        }
        association = getattr(certificate, 'user_client_certificate', None)
        if association is not None:
            message_type = (
                NotificationModel.NotificationMessageType.USER_CERT_EXPIRING
                if message_type == NotificationModel.NotificationMessageType.CERT_EXPIRING
                else NotificationModel.NotificationMessageType.USER_CERT_EXPIRED
            )
            message_data.update(
                username=association.user.username,
                identifier=association.identifier,
            )

        issued_credential_domain_id = self._domains_by_certificate.get(certificate.pk)
        if event == 'CERTIFICATE_EXPIRED':
            self._solve_expiring_alert(certificate, issued_credential_domain_id)
        key: tuple[str, int, int | None]

        if issued_credential_domain_id is not None:
            key = (event, certificate.pk, issued_credential_domain_id)
            if key not in self._existing_notifications:
                notification = NotificationModel.objects.create(
                    domain_id=issued_credential_domain_id,
                    certificate=certificate,
                    created_at=timezone.now(),
                    notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                    notification_type=notification_type,
                    message_type=message_type,
                    event=event,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
                self._existing_notifications.add(key)
        else:
            key = (event, certificate.pk, None)
            if key not in self._existing_notifications:
                notification = NotificationModel.objects.create(
                    certificate=certificate,
                    created_at=timezone.now(),
                    notification_source=NotificationModel.NotificationSource.CERTIFICATE,
                    notification_type=notification_type,
                    message_type=message_type,
                    event=event,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
                self._existing_notifications.add(key)
