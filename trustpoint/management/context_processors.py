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
_BADGE_CACHE_INTERVAL_SECONDS = 30
_cycle_check_state = {'last': 0.0}
_badge_cache: dict[str, Any] = {'last': 0.0, 'counts': {}}


def reset_notification_badge_cache() -> None:
    """Clear the per-process badge cache (used by tests and after bulk status changes)."""
    _badge_cache['last'] = 0.0
    _badge_cache['counts'] = {}


def notification_alerts(request: HttpRequest) -> dict[str, Any]:
    """Provide counts of unread warning and critical notifications for the global header."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    now = time.monotonic()
    if now - _cycle_check_state['last'] >= _CYCLE_CHECK_INTERVAL_SECONDS:
        _cycle_check_state['last'] = now
        check_notification_cycle()

    if now - _badge_cache['last'] >= _BADGE_CACHE_INTERVAL_SECONDS:
        counts = NotificationModel.objects.filter(
            statuses__status=NotificationStatus.StatusChoices.NEW,
            notification_type__in=[
                NotificationModel.NotificationTypes.CRITICAL,
                NotificationModel.NotificationTypes.WARNING,
            ],
        ).aggregate(
            critical=Count(
                'pk', filter=Q(notification_type=NotificationModel.NotificationTypes.CRITICAL), distinct=True
            ),
            warning=Count('pk', filter=Q(notification_type=NotificationModel.NotificationTypes.WARNING), distinct=True),
        )
        _badge_cache['counts'] = {
            'notification_alert_critical_count': counts['critical'],
            'notification_alert_warning_count': counts['warning'],
            'notification_alert_total': counts['critical'] + counts['warning'],
        }
        _badge_cache['last'] = now

    return dict(_badge_cache['counts'])


def ui_config(request: HttpRequest) -> dict[str, Any]:
    """Provide UI configuration for use in templates."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    return {
        'is_simplified_mode': request.user.view_mode == 'simplified',
    }
