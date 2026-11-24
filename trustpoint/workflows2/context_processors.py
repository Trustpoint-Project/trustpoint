# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Context processors for Workflow 2 navigation badges."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from django.db.models import Count, Q

from workflows2.models import Workflow2Approval, Workflow2Instance

if TYPE_CHECKING:
    from django.http import HttpRequest

_CACHE_INTERVAL_SECONDS = 30
_cache: dict[str, Any] = {'last': 0.0, 'counts': {}}


def reset_waiting_counts_cache() -> None:
    """Clear the per-process waiting-count cache after a workflow transition."""
    _cache['last'] = 0.0
    _cache['counts'] = {}


def waiting_counts(request: HttpRequest) -> dict[str, Any]:
    """Provide the global count of workflow items waiting for user action."""
    if not hasattr(request, 'user') or not request.user.is_authenticated:
        return {}

    now = time.monotonic()
    if now - _cache['last'] >= _CACHE_INTERVAL_SECONDS:
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
        _cache['counts'] = {
            'workflow_waiting_approval_count': pending_approvals,
            'workflow_waiting_paused_count': paused_instances,
            'workflow_waiting_error_count': error_instances,
            'workflow_waiting_total': pending_approvals + paused_instances + error_instances,
        }
        _cache['last'] = now

    return dict(_cache['counts'])
