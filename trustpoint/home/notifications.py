# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Read-only notification summaries for Dashboard.

NEW is an unread marker, not an unresolved marker. SOLV marks solved.
A notification without SOLV is considered open in this preview; other terminal
states are excluded as well. This is deliberately separate from generation.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.db.models import Case, IntegerField, Value, When
from django.urls import reverse
from django.utils import timezone

from management.models import NotificationModel, NotificationStatus

TERMINAL_STATUSES = (
    NotificationStatus.StatusChoices.SOLVED,
    NotificationStatus.StatusChoices.CLOSED,
    NotificationStatus.StatusChoices.DELETED,
    NotificationStatus.StatusChoices.REJECTED,
)


def notification_to_dict(item: NotificationModel) -> dict[str, Any]:
    """Serialize safe display fields; no HTML, secrets or message_data."""
    associated = next(
        (str(obj) for obj in (item.certificate, item.device, item.issuing_ca, item.domain) if obj is not None), None
    )
    return {
        'id': item.pk,
        'severity': item.notification_type,
        'source': item.get_notification_source_display(),
        'title': str(item.short_translated),
        'associated_object': associated,
        'created_at': item.created_at.isoformat(),
        'url': reverse('management:notification_details', kwargs={'pk': item.pk}),
    }


def get_notification_payload(*, activity_days: int = 30, now: datetime | None = None) -> dict[str, Any]:
    """Read most relevant open notifications and recent informational messages."""
    if activity_days not in (7, 30, 90):
        msg = 'activity_days must be 7, 30, or 90'
        raise ValueError(msg)
    timestamp = now if now is not None else timezone.now()
    active = NotificationModel.objects.exclude(statuses__status__in=TERMINAL_STATUSES).distinct()
    alerts = active.filter(
        notification_type__in=(
            NotificationModel.NotificationTypes.CRITICAL,
            NotificationModel.NotificationTypes.WARNING,
        )
    )
    counts = {
        'critical': alerts.filter(notification_type=NotificationModel.NotificationTypes.CRITICAL).count(),
        'warning': alerts.filter(notification_type=NotificationModel.NotificationTypes.WARNING).count(),
    }
    ordered_alerts = (
        alerts.annotate(
            priority=Case(
                When(notification_type=NotificationModel.NotificationTypes.CRITICAL, then=Value(0)),
                default=Value(1),
                output_field=IntegerField(),
            )
        )
        .select_related('certificate', 'device', 'issuing_ca', 'domain')
        .order_by('priority', '-created_at', '-pk')[:5]
    )
    activity = (
        NotificationModel.objects.filter(
            notification_type__in=(NotificationModel.NotificationTypes.INFO, NotificationModel.NotificationTypes.SETUP),
            created_at__gte=timestamp - timedelta(days=activity_days),
            created_at__lte=timestamp,
        )
        .select_related('certificate', 'device', 'issuing_ca', 'domain')
        .order_by('-created_at', '-pk')[:5]
    )
    return {
        'as_of': timestamp.isoformat(),
        'activity_days': activity_days,
        'alerts': {
            'counts': counts,
            'total': counts['critical'] + counts['warning'],
            'items': [notification_to_dict(item) for item in ordered_alerts],
        },
        'activity': {'items': [notification_to_dict(item) for item in activity]},
        'source': 'NotificationModel',
        'is_complete_audit_log': False,
    }
