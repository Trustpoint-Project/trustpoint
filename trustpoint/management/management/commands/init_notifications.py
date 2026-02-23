"""Django management command to initialize notification scheduling."""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from management.models import NotificationConfig


class Command(BaseCommand):
    """Initialize notification scheduling in Django-Q2."""

    help = 'Initialize the notification check scheduling via Django-Q2'

    def add_arguments(self, parser: Any) -> None:
        """Add command arguments.

        Args:
            parser: The argument parser.
        """
        parser.add_argument(
            '--interval-minutes',
            type=float,
            default=5,
            help='Number of minutes between notification checks (default: 5)'
        )

    def handle(self, *args: Any, **kwargs: dict[str, Any]) -> None:  # noqa: ARG002
        """Entrypoint for the command.

        Args:
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.
        """
        interval_minutes = kwargs.get('interval_minutes', 5)
        interval_hours = interval_minutes / 60

        notification_config = NotificationConfig.get()

        if not notification_config.enabled:
            self.stdout.write(
                self.style.WARNING(
                    'Notifications are currently disabled. '
                    'Enable them in Management > Settings to start notification checks.'
                )
            )
            return

        try:
            notification_config.schedule_next_notification_check(cycle_interval_hours=interval_hours)
            self.stdout.write(
                self.style.SUCCESS(
                    f'✓ Notification checking initialized successfully!\n'
                    f'  Next check scheduled in {interval_minutes} minute(s).\n'
                    f'  Make sure the Q Cluster is running: uv run trustpoint/manage.py qcluster'
                )
            )
        except Exception as exc:
            self.stdout.write(self.style.ERROR(f'Failed to initialize notification scheduling: {exc}'))
            raise
