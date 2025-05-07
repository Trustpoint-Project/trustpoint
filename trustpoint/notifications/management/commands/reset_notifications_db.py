"""This module defines a Django management command to delete all existing notifications."""

from typing import Any

from django.core.management.base import BaseCommand
from notifications.models import NotificationModel

from trustpoint.settings import DOCKER_CONTAINER


class Command(BaseCommand):
    """A Django management command to delete all existing notifications.

    If running inside a Docker container, the command deletes notifications
    without user confirmation. Otherwise, it prompts the user for confirmation.
    """

    help = 'Deletes all existing notifications'

    def handle(self, **options: Any) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            **options: A variable-length argument.
        """
        if DOCKER_CONTAINER:
            self.delete_notifications()
            return

        confirm = input('Are you sure you want to delete all notifications? Type "yes" to confirm: ')
        if confirm.strip().lower() == 'yes':
            self.delete_notifications()
        else:
            self.stdout.write(self.style.WARNING('Deletion cancelled.'))

    def delete_notifications(self) -> None:
        """Deletes all notifications and reports the result."""
        count, _ = NotificationModel.objects.all().delete()
        self.stdout.write(self.style.SUCCESS(f'Deleted {count} notifications.'))
