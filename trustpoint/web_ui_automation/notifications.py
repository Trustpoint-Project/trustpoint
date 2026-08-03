# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Trustpoint notification integration for Web UI automation failures."""

from __future__ import annotations

from typing import TYPE_CHECKING

from management.models.notifications import (
    NotificationMessageModel,
    NotificationModel,
    NotificationStatus,
)

if TYPE_CHECKING:
    from web_ui_automation.models import WebUiAutomationJob


def create_job_attention_notification(job: WebUiAutomationJob) -> NotificationModel:
    """Create a device-scoped warning notification for a job requiring attention."""
    device = job.assignment.automation_device.device
    message = NotificationMessageModel.objects.create(
        short_description=f'Web UI automation requires attention for {device}',
        long_description=(
            f'Operation {job.operation} requires attention for profile '
            f'{job.assignment.workflow_definition.name}. '
            f'Failed step: {job.failed_step_id or "unknown"}. '
            f'Error: {job.error_message or "No error message was recorded."}'
        ),
    )
    notification = NotificationModel.objects.create(
        notification_type=NotificationModel.NotificationTypes.WARNING,
        notification_source=NotificationModel.NotificationSource.DEVICE,
        message_type=NotificationModel.NotificationMessageType.CUSTOM,
        message=message,
        device=device,
        event=f'web-ui-automation-job:{job.pk}',
    )
    new_status, _created = NotificationStatus.objects.get_or_create(
        status=NotificationStatus.StatusChoices.NEW
    )
    notification.statuses.add(new_status)
    return notification
