"""Asynchronous tasks for management operations."""

from __future__ import annotations

import logging

from django.core.management import call_command
from django.core.management.base import CommandError

logger = logging.getLogger(__name__)


def execute_all_notifications() -> None:
    """Execute all notification checks sequentially using Django-Q2.

    This function is executed by Django-Q2 as a background task.
    It calls the run_all_notifications management command which runs
    all notification-related checks in sequence.

    Raises:
        CommandError: If any of the notification commands fail.
    """
    logger.info('Starting execution of all notifications via Django-Q2')

    try:
        call_command('run_all_notifications')
        logger.info('All notifications executed successfully via Django-Q2')
    except CommandError:
        logger.exception('CommandError while executing notifications')
        raise
    except Exception:
        logger.exception('Unexpected error while executing notifications')
        raise

