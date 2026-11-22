# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to check the validity of CRLs.

This module defines a Django management command that checks for expiring
or expired Certificate Revocation Lists (CRLs). Expiring CRLs trigger a
WARNING notification, while expired CRLs trigger a CRITICAL notification.
Notifications are created only if they do not already exist for the given
CRL and event.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

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

        active_crls = list(CrlModel.objects.filter(is_active=True, next_update__isnull=False).select_related('ca'))

        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        from pki.models import DomainModel  # noqa: PLC0415

        ca_ids = {crl.ca_id for crl in active_crls if crl.ca_id is not None}
        domains_by_ca: dict[int, list[DomainModel]] = {}
        for domain in DomainModel.objects.filter(issuing_ca_id__in=ca_ids).only('id', 'issuing_ca_id'):
            if domain.issuing_ca_id is not None:
                domains_by_ca.setdefault(domain.issuing_ca_id, []).append(domain)

        # One query for the whole sweep instead of one exists() per CRL and domain.
        existing: set[tuple[str, int | None, int | None]] = set(
            NotificationModel.objects.filter(event__startswith='CRL_').values_list(
                'event', 'issuing_ca_id', 'domain_id'
            )
        )

        for crl in active_crls:
            next_update = crl.next_update
            if next_update is None:
                continue

            if next_update <= current_time:
                self._create_notification(
                    crl=crl,
                    event=f'CRL_EXPIRED_{crl.pk}',
                    notification_type=NotificationModel.NotificationTypes.CRITICAL,
                    message_type=NotificationModel.NotificationMessageType.CRL_EXPIRED,
                    new_status=new_status,
                    existing=existing,
                    domains_by_ca=domains_by_ca,
                )
            elif next_update <= expiring_threshold:
                self._create_notification(
                    crl=crl,
                    event=f'CRL_EXPIRING_{crl.pk}',
                    notification_type=NotificationModel.NotificationTypes.WARNING,
                    message_type=NotificationModel.NotificationMessageType.CRL_EXPIRING,
                    new_status=new_status,
                    existing=existing,
                    domains_by_ca=domains_by_ca,
                )

    def _create_notification(  # noqa: PLR0913 - one call site builds the full notification
        self,
        crl: CrlModel,
        event: str,
        notification_type: str | NotificationModel.NotificationTypes,
        message_type: str | NotificationModel.NotificationMessageType,
        new_status: NotificationStatus,
        *,
        existing: set[tuple[str, int | None, int | None]],
        domains_by_ca: dict[int, list[Any]],
    ) -> None:
        """Create a notification for a CRL.

        Skips notification creation if one already exists for the given event.
        If the CRL's CA is associated with domains, creates a separate notification for each domain.
        Otherwise, creates a single notification without domain association.

        Args:
            crl: The CRL model instance.
            event: A unique event identifier for deduplication.
            notification_type: The notification severity level.
            message_type: The notification message type enum value.
            new_status: The NEW status instance to attach.
            existing: Event keys already present, loaded once by the caller.
            domains_by_ca: Domains grouped by issuing CA, loaded once by the caller.
        """
        ca_name = crl.ca.unique_name if crl.ca else 'Unknown CA'
        next_update_str = crl.next_update.strftime('%Y-%m-%d %H:%M:%S') if crl.next_update else 'N/A'

        message_data = {
            'ca_name': ca_name,
            'next_update': next_update_str,
        }

        domains_using_ca = domains_by_ca.get(crl.ca_id, []) if crl.ca_id else []

        if domains_using_ca:
            for domain in domains_using_ca:
                key = (event, crl.ca_id, domain.pk)
                if key in existing:
                    continue
                notification = NotificationModel.objects.create(
                    domain=domain,
                    issuing_ca=crl.ca,
                    created_at=timezone.now(),
                    notification_source=NotificationModel.NotificationSource.ISSUING_CA,
                    notification_type=notification_type,
                    message_type=message_type,
                    event=event,
                    message_data=message_data,
                )
                notification.statuses.add(new_status)
                existing.add(key)
        else:
            key = (event, crl.ca_id, None)
            if key in existing:
                return
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
            existing.add(key)
