"""Django signals for the management app."""

from __future__ import annotations

import logging

from django.db.models.signals import post_migrate
from django.dispatch import receiver

from management.models import NotificationConfig

logger = logging.getLogger(__name__)


@receiver(post_migrate)
def initialize_notification_scheduling(sender: object, **kwargs: dict) -> None:  # noqa: ARG001
    """Initialize notification scheduling after database migrations.

    This signal handler runs after migrations are applied and ensures that
    notification checking is scheduled to begin automatically.

    Args:
        sender: The app config that triggered the migration.
        **kwargs: Additional keyword arguments from the signal.
    """
    try:
        notification_config = NotificationConfig.get()

        if notification_config.notification_cycle_enabled and notification_config.enabled:
            # Schedule the first notification check
            notification_config.schedule_next_notification_check()
            logger.info('Notification scheduling initialized automatically via post_migrate signal')
        else:
            logger.info(
                'Notification scheduling skipped: cycle_enabled=%s, enabled=%s',
                notification_config.notification_cycle_enabled,
                notification_config.enabled,
            )
    except Exception:
        logger.exception('Failed to initialize notification scheduling')
