"""Management command to check domains without Issuing CA assignments."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone
from notifications.models import NotificationModel, NotificationStatus
from pki.models import DomainModel


class Command(BaseCommand):
    """A Django management command to identify domains without an Issuing CA and create notifications for them."""

    help = 'Check domains without issuing CA assignments.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._check_domain_issuing_ca()
        self.stdout.write(self.style.SUCCESS('Domain Issuing CA check completed.'))

    def _check_domain_issuing_ca(self) -> None:
        """Create notifications for domains without an Issuing CA."""
        domains_without_issuing_ca = DomainModel.objects.filter(issuing_ca__isnull=True)
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        for domain in domains_without_issuing_ca:
            if not NotificationModel.objects.filter(event='DOMAIN_NO_ISSUING_CA', domain=domain).exists():
                notification = NotificationModel.objects.create(
                    domain=domain,
                    created_at=timezone.now(),
                    notification_source=NotificationModel.NotificationSource.DOMAIN,
                    notification_type=NotificationModel.NotificationTypes.INFO,
                    message_type=NotificationModel.NotificationMessageType.DOMAIN_NO_ISSUING_CA,
                    event='DOMAIN_NO_ISSUING_CA',
                    message_data={'unique_name': domain.unique_name},
                )
                notification.statuses.add(new_status)
