# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Context processors for the management app."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from django.db.models import Count, Q

from management.models import NotificationModel, NotificationStatus
from management.notifications import check_notification_cycle

if TYPE_CHECKING:
    from django.http import HttpRequest

_CYCLE_CHECK_INTERVAL_SECONDS = 60
_cycle_check_state = {'last': 0.0}


def notification_alerts(request: HttpRequest) -> dict[str, Any]:
    """Provide counts of unread warning and critical notifications for the global header."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    now = time.monotonic()
    if now - _cycle_check_state['last'] >= _CYCLE_CHECK_INTERVAL_SECONDS:
        _cycle_check_state['last'] = now
        check_notification_cycle()

    counts = NotificationModel.objects.filter(
        statuses__status=NotificationStatus.StatusChoices.NEW,
        notification_type__in=[
            NotificationModel.NotificationTypes.CRITICAL,
            NotificationModel.NotificationTypes.WARNING,
        ],
    ).aggregate(
        critical=Count('pk', filter=Q(notification_type=NotificationModel.NotificationTypes.CRITICAL), distinct=True),
        warning=Count('pk', filter=Q(notification_type=NotificationModel.NotificationTypes.WARNING), distinct=True),
    )

    unread_critical = counts['critical']
    unread_warning = counts['warning']

    return {
        'notification_alert_critical_count': unread_critical,
        'notification_alert_warning_count': unread_warning,
        'notification_alert_total': unread_critical + unread_warning,
    }


def ui_config(request: HttpRequest) -> dict[str, Any]:
    """Provide UI configuration for use in templates."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    return {
        'is_simplified_mode': request.user.view_mode == 'simplified',
    }
