"""Asynchronous tasks for management operations."""

from __future__ import annotations

import logging

from django.core.management import call_command
from django.core.management.base import CommandError

from management.models import NotificationConfig

logger = logging.getLogger(__name__)


def execute_all_notifications() -> None:
    """Execute all notification checks sequentially using Django-Q2.

    This function is executed by Django-Q2 as a background task.
    It calls the run_all_notifications management command which runs
    all notification-related checks in sequence.

    After execution, it automatically schedules the next notification check
    based on the NotificationConfig settings.

    Raises:
        CommandError: If any of the notification commands fail.
    """
    logger.info('Starting execution of all notifications via Django-Q2')

    try:
        call_command('run_all_notifications')
        logger.info('All notifications executed successfully via Django-Q2')

        # Schedule the next notification check
        # Explicitly fetch fresh data from DB to avoid stale cache in task context
        notification_config = NotificationConfig.get()
        notification_config.refresh_from_db()

        logger.info(
            'Notification config state: enabled=%s, cycle_enabled=%s',
            notification_config.enabled,
            notification_config.notification_cycle_enabled
        )

        if notification_config.enabled and notification_config.notification_cycle_enabled:
            notification_config.schedule_next_notification_check()
            logger.info('Next notification check scheduled successfully')
        else:
            logger.warning(
                'Notifications are disabled (enabled=%s, cycle_enabled=%s), skipping rescheduling',
                notification_config.enabled,
                notification_config.notification_cycle_enabled
            )

    except CommandError:
        logger.exception('CommandError while executing notifications')
        raise
    except Exception:
        logger.exception('Unexpected error while executing notifications')
        raise

