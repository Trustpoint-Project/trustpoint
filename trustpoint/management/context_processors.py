"""Context processors for the management app."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from management.models import NotificationModel, NotificationStatus

if TYPE_CHECKING:
    from django.http import HttpRequest


def notification_alerts(request: HttpRequest) -> dict[str, Any]:
    """Provide counts of unread warning and critical notifications for the global header."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    unread_critical = NotificationModel.objects.filter(
        statuses__status=NotificationStatus.StatusChoices.NEW,
        notification_type=NotificationModel.NotificationTypes.CRITICAL,
    ).count()

    unread_warning = NotificationModel.objects.filter(
        statuses__status=NotificationStatus.StatusChoices.NEW,
        notification_type=NotificationModel.NotificationTypes.WARNING,
    ).count()

    return {
        'notification_alert_critical_count': unread_critical,
        'notification_alert_warning_count': unread_warning,
        'notification_alert_total': unread_critical + unread_warning,
    }
