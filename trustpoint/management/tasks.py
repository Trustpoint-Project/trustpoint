# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Asynchronous tasks for management operations."""

from __future__ import annotations

import logging
from datetime import timedelta

from django.core.management import call_command
from django.utils import timezone

from management.models import NotificationConfig
from management.services.audit_signing import maybe_sign_checkpoint

logger = logging.getLogger(__name__)


def sign_audit_checkpoint() -> None:
    """Retry or time-based checkpoint signing; safe to run repeatedly.

    This function is executed by Django-Q2 as a background task. The normal
    trigger is the post-commit hook after audit events, so this task is the
    safety net for low-traffic periods and earlier signing failures.
    """
    maybe_sign_checkpoint()


def execute_all_notifications() -> None:
    """Execute all notification checks sequentially using Django-Q2.

    This function is executed by Django-Q2 as a background task.
    It calls the run_all_notifications management command which runs
    all notification-related checks in sequence.

    After execution, it automatically schedules the next notification check
    based on the NotificationConfig settings.

    Raises:
        Exception: If the checks fail or the next check cannot be scheduled.
    """
    logger.info('Starting execution of all notifications via Django-Q2')

    notification_config = NotificationConfig.get()
    if notification_config.enabled and notification_config.notification_cycle_enabled:
        # Move the expected next run before checking, so a healthy but slow cycle is not reported as overdue.
        notification_config.last_notification_check_started_at = timezone.now() + timedelta(
            hours=notification_config.notification_cycle_interval_hours
        )
        notification_config.save(update_fields=['last_notification_check_started_at'])

    error: Exception | None = None
    try:
        call_command('run_all_notifications')
        logger.info('All notifications executed successfully via Django-Q2')
    except Exception as exc:
        logger.exception('Unexpected error while executing notifications')
        error = exc

    # Always schedule the next check: one failing check must not stop all future notification checks.
    notification_config.refresh_from_db()
    if notification_config.enabled and notification_config.notification_cycle_enabled:
        notification_config.schedule_next_notification_check()
        logger.info('Next notification check scheduled successfully')
    else:
        logger.warning(
            'Notifications are disabled (enabled=%s, cycle_enabled=%s), skipping rescheduling',
            notification_config.enabled,
            notification_config.notification_cycle_enabled,
        )

    if error is not None:
        raise error
