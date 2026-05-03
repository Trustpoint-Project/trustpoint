"""Resolve request-facing decisions from Workflow 2 runtime state."""

from __future__ import annotations

from enum import Enum
from typing import Any

from workflows2.models import Workflow2Approval, Workflow2Run


class Workflow2RequestDecision(Enum):
    """Describe what one request should do after consulting Workflow 2."""

    CONTINUE = 'continue'
    WAIT = 'wait'
    REJECT = 'reject'
    FAIL = 'fail'


def resolve_request_decision(run: Workflow2Run | Any) -> Workflow2RequestDecision:
    """Return the request-facing decision represented by one workflow run.

    Request workflows can branch after an approval decision and still end with an
    aggregate run status of ``succeeded``. In that case the approval decision is
    authoritative for request gating, not the final execution status alone.
    """
    run_status = str(getattr(run, 'status', '') or '')
    approval_statuses = _approval_statuses_for_run(run)

    decision = Workflow2RequestDecision.FAIL
    if Workflow2Approval.STATUS_REJECTED in approval_statuses:
        decision = Workflow2RequestDecision.REJECT
    elif Workflow2Approval.STATUS_EXPIRED in approval_statuses:
        decision = Workflow2RequestDecision.FAIL
    elif run_status == Workflow2Run.STATUS_REJECTED:
        decision = Workflow2RequestDecision.REJECT
    elif (
        Workflow2Approval.STATUS_PENDING in approval_statuses
        or run_status in {
        Workflow2Run.STATUS_QUEUED,
        Workflow2Run.STATUS_RUNNING,
        Workflow2Run.STATUS_AWAITING,
        Workflow2Run.STATUS_PAUSED,
        }
    ):
        decision = Workflow2RequestDecision.WAIT
    elif run_status in {
        Workflow2Run.STATUS_FAILED,
        Workflow2Run.STATUS_CANCELLED,
        Workflow2Run.STATUS_STOPPED,
    }:
        decision = Workflow2RequestDecision.FAIL
    elif run_status == Workflow2Run.STATUS_SUCCEEDED:
        decision = Workflow2RequestDecision.CONTINUE
    return decision


def _approval_statuses_for_run(run: Workflow2Run | Any) -> set[str]:
    """Return all approval statuses recorded for one persisted workflow run."""
    if not isinstance(run, Workflow2Run) or run.pk is None:
        return set()

    return set(
        Workflow2Approval.objects.filter(instance__run=run).values_list('status', flat=True)
    )
