# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Record operational alerts without interrupting the operation being reported."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from management.models import NotificationConfig, NotificationModel, NotificationStatus

logger = logging.getLogger(__name__)


def notify_operational_issue(
    event: str,
    message_type: NotificationModel.NotificationMessageType,
    severity: NotificationModel.NotificationTypes,
    message_data: dict[str, Any],
    *,
    strict: bool = False,
) -> None:
    """Deduplicate an issue and reopen it if it recurs after recovery."""
    try:
        with transaction.atomic():
            if NotificationConfig.objects.select_for_update().filter(enabled=True).first() is None:
                return
            defaults = {
                'notification_source': NotificationModel.NotificationSource.SYSTEM,
                'notification_type': severity,
                'message_type': message_type,
                'message_data': message_data,
            }
            # shortcut: event is not unique, so concurrent inserts can leave duplicate alert rows;
            # always reuse the oldest one and merge them only if that becomes a real problem.
            notification = NotificationModel.objects.filter(event=event).order_by('pk').first()
            created = notification is None
            if notification is None:
                notification = NotificationModel.objects.create(event=event, **defaults)
            escalated = notification.notification_type != severity
            if not created:
                changed = [key for key, value in defaults.items() if getattr(notification, key) != value]
                for key in changed:
                    setattr(notification, key, defaults[key])
                if changed:
                    notification.save(update_fields=changed)
            recovered = notification.statuses.filter(status=NotificationStatus.StatusChoices.SOLVED).exists()
            if created or recovered or escalated:
                notification.statuses.remove(
                    *notification.statuses.filter(status=NotificationStatus.StatusChoices.SOLVED)
                )
                new, _ = NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.NEW)
                notification.statuses.add(new)
    except Exception:
        if strict:
            raise
        logger.exception('Unable to record operational notification %s.', event)


def resolve_operational_issue(event: str, *, strict: bool = False) -> None:
    """Mark a recovered issue solved, preserving its history."""
    try:
        with transaction.atomic():
            for notification in NotificationModel.objects.filter(event=event).exclude(
                statuses__status=NotificationStatus.StatusChoices.SOLVED,
            ):
                solved, _ = NotificationStatus.objects.get_or_create(status=NotificationStatus.StatusChoices.SOLVED)
                notification.statuses.add(solved)
                notification.statuses.remove(*notification.statuses.filter(status=NotificationStatus.StatusChoices.NEW))
    except Exception:
        if strict:
            raise
        logger.exception('Unable to resolve operational notification %s.', event)


def check_notification_cycle() -> None:
    """Detect a missed scheduled cycle from web requests, independently of the worker."""
    config = NotificationConfig.get()
    event = 'NOTIFICATION_CHECK_OVERDUE'
    if not config.enabled or not config.notification_cycle_enabled:
        resolve_operational_issue(event)
        return
    # The existing timestamp records the next scheduled run, despite its field name.
    due = config.last_notification_check_started_at
    grace = timedelta(hours=max(config.notification_cycle_interval_hours, 5 / 60))
    if due is not None and timezone.now() <= due + grace:
        resolve_operational_issue(event)
        return
    notify_operational_issue(
        event,
        NotificationModel.NotificationMessageType.NOTIFICATION_CHECK_OVERDUE,
        NotificationModel.NotificationTypes.WARNING,
        {},
    )
