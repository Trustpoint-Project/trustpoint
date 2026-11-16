# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Report failed workflows and approvals that passed their configured deadline."""

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from management.models import NotificationConfig, NotificationModel
from management.notifications import notify_operational_issue, resolve_operational_issue
from workflows2.models import Workflow2Approval, Workflow2Instance


class Command(BaseCommand):
    """Use stored workflow states and approval deadlines without changing execution."""

    help = 'Check failed workflow instances and overdue approval deadlines.'

    def handle(self, *args: Any, **options: Any) -> None:  # noqa: ARG002
        """Deduplicate alerts by workflow instance or approval."""
        if not NotificationConfig.get().enabled:
            return
        reported_failures = [
            event.removeprefix('WORKFLOW_FAILED_')
            for event in NotificationModel.objects.filter(
                message_type=NotificationModel.NotificationMessageType.WORKFLOW_FAILED,
                event__startswith='WORKFLOW_FAILED_',
            ).values_list('event', flat=True)
        ]
        for instance in (
            Workflow2Instance.objects.filter(
                status__in=(Workflow2Instance.STATUS_ERROR, Workflow2Instance.STATUS_TIMED_OUT),
            )
            .exclude(pk__in=reported_failures)
            .select_related('definition')
        ):
            notify_operational_issue(
                f'WORKFLOW_FAILED_{instance.pk}',
                NotificationModel.NotificationMessageType.WORKFLOW_FAILED,
                NotificationModel.NotificationTypes.WARNING,
                {'workflow': instance.definition.name, 'instance_id': str(instance.pk)},
                strict=True,
            )
        now = timezone.now()
        active_events = []
        for approval in Workflow2Approval.objects.filter(
            expires_at__lte=now,
            status__in=(Workflow2Approval.STATUS_PENDING, Workflow2Approval.STATUS_EXPIRED),
            instance__status__in=(Workflow2Instance.STATUS_AWAITING, Workflow2Instance.STATUS_TIMED_OUT),
        ).select_related('instance__definition'):
            if approval.expires_at is None:
                continue
            event = f'WORKFLOW_APPROVAL_OVERDUE_{approval.pk}'
            active_events.append(event)
            notify_operational_issue(
                event,
                NotificationModel.NotificationMessageType.WORKFLOW_APPROVAL_OVERDUE,
                NotificationModel.NotificationTypes.WARNING,
                {
                    'workflow': approval.instance.definition.name,
                    'approval_id': str(approval.pk),
                    'expires_at': approval.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                },
                strict=True,
            )
        for event in (
            NotificationModel.objects.filter(
                message_type=NotificationModel.NotificationMessageType.WORKFLOW_APPROVAL_OVERDUE,
            )
            .exclude(event__in=active_events)
            .exclude(
                statuses__status='SOLV',
            )
            .values_list('event', flat=True)
        ):
            resolve_operational_issue(event, strict=True)
        self.stdout.write(self.style.SUCCESS('Workflow notification check completed.'))
