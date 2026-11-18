# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Context processors for Workflow 2 navigation badges."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db.models import Count, Q

from workflows2.models import Workflow2Approval, Workflow2Instance

if TYPE_CHECKING:
    from django.http import HttpRequest


def waiting_counts(request: HttpRequest) -> dict[str, Any]:
    """Provide the global count of workflow items waiting for user action."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    pending_approvals = Workflow2Approval.objects.filter(
        status=Workflow2Approval.STATUS_PENDING,
        instance__status=Workflow2Instance.STATUS_AWAITING,
    ).count()
    instance_counts = Workflow2Instance.objects.aggregate(
        paused=Count('pk', filter=Q(status=Workflow2Instance.STATUS_PAUSED)),
        error=Count('pk', filter=Q(status=Workflow2Instance.STATUS_ERROR)),
    )
    paused_instances = instance_counts['paused']
    error_instances = instance_counts['error']

    return {
        'workflow_waiting_approval_count': pending_approvals,
        'workflow_waiting_paused_count': paused_instances,
        'workflow_waiting_error_count': error_instances,
        'workflow_waiting_total': pending_approvals + paused_instances + error_instances,
    }
