"""This module contains a Django management command to generate setup related notifications."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone
from home.models import NotificationModel, NotificationStatus


class Command(BaseCommand):
    """Django management command to set up initial Trustpoint notifications.

    This command initializes and sets up necessary notifications for Trustpoint.
    """

    help = 'Set up initial Trustpoint notifications.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        self._trustpoint_setup_notifications()
        self.stdout.write(self.style.SUCCESS('Successfully set up Trustpoint notifications.'))

    def _trustpoint_setup_notifications(self) -> None:
        """Task to create initial setup notifications for a new Trustpoint instance.

        This includes a welcome notification and links to the project's GitHub repository and homepage.
        """
        new_status, _ = NotificationStatus.objects.get_or_create(status='NEW')

        if not NotificationModel.objects.filter(event='TRUSTPOINT_DOCUMENTATION').exists():
            link = '<a href="https://trustpoint.readthedocs.io" target="_blank">Trustpoint Documentation</a>'

            notification = NotificationModel.objects.create(
                event='TRUSTPOINT_DOCUMENTATION',
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.SYSTEM,
                notification_type=NotificationModel.NotificationTypes.INFO,
                message_type=NotificationModel.NotificationMessageType.TRUSTPOINT_DOCUMENTATION,
                message_data={'link': link},
            )
            notification.statuses.add(new_status)

        # Check if the GitHub and homepage links notification has already been created
        if not NotificationModel.objects.filter(event='TRUSTPOINT_PROJECT_INFO').exists():
            url_github = 'https://github.com/TrustPoint-Project'
            url_homepage = 'https://industrial-security.io'

            notification = NotificationModel.objects.create(
                event='TRUSTPOINT_PROJECT_INFO',
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.SYSTEM,
                notification_type=NotificationModel.NotificationTypes.INFO,
                message_type=NotificationModel.NotificationMessageType.TRUSTPOINT_PROJECT_INFO,
                message_data={'url_github': url_github, 'url_homepage': url_homepage},
            )
            notification.statuses.add(new_status)

        # Check if the welcome notification has already been created
        if not NotificationModel.objects.filter(event='WELCOME_TRUSTPOINT').exists():
            notification = NotificationModel.objects.create(
                event='WELCOME_TRUSTPOINT',
                created_at=timezone.now(),
                notification_source=NotificationModel.NotificationSource.SYSTEM,
                notification_type=NotificationModel.NotificationTypes.INFO,
                message_type=NotificationModel.NotificationMessageType.WELCOME_MESSAGE,
            )
            notification.statuses.add(new_status)
