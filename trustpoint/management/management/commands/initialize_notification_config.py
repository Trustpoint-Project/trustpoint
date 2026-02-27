"""Management command to initialize the notifications configuration."""
from typing import Any

from django.core.management.base import BaseCommand
from management.models import NotificationConfig


class Command(BaseCommand):
    """Management command to initialize NotificationConfig with default values."""

    help = 'Initializes the default NotificationConfig singleton if it does not exist yet.'

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Create the NotificationConfig singleton with default values if missing."""
        _config, created = NotificationConfig.objects.get_or_create(pk=1)
        if created:
            self.stdout.write(self.style.SUCCESS('NotificationConfig created with default values.'))
        else:
            self.stdout.write('NotificationConfig already exists, nothing to do.')
