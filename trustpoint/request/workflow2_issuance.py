"""Helpers for interpreting Workflow 2 outcomes during certificate issuance."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, cast

from workflows2.models import Workflow2Run

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext
    from workflows2.services.dispatch import DispatchOutcome


WORKFLOW2_PENDING_RUN_STATUSES: set[str] = {
    Workflow2Run.STATUS_QUEUED,
    Workflow2Run.STATUS_RUNNING,
    Workflow2Run.STATUS_AWAITING,
    Workflow2Run.STATUS_PAUSED,
}

WORKFLOW2_NEGATIVE_RUN_STATUSES: set[str] = {
    Workflow2Run.STATUS_REJECTED,
    Workflow2Run.STATUS_FAILED,
    Workflow2Run.STATUS_CANCELLED,
    Workflow2Run.STATUS_STOPPED,
}


class Workflow2IssuanceDecision(Enum):
    """Describe whether certificate issuance should continue after Workflow 2."""

    CONTINUE = 'continue'
    WAIT = 'wait'
    REJECT = 'reject'
    FAIL = 'fail'


def get_workflow2_dispatch_outcome(context: BaseRequestContext) -> DispatchOutcome | None:
    """Return the Workflow 2 dispatch outcome stored on the request context."""
    outcome = getattr(context, 'workflow2_outcome', None)
    return cast('DispatchOutcome | None', outcome)


def get_workflow2_issuance_decision(context: BaseRequestContext) -> Workflow2IssuanceDecision:
    """Return the issuance decision implied by the current Workflow 2 outcome."""
    outcome = get_workflow2_dispatch_outcome(context)
    if outcome is None:
        return Workflow2IssuanceDecision.CONTINUE

    run_status = str(outcome.run.status)
    if run_status == Workflow2Run.STATUS_SUCCEEDED:
        return Workflow2IssuanceDecision.CONTINUE
    if run_status in WORKFLOW2_PENDING_RUN_STATUSES:
        return Workflow2IssuanceDecision.WAIT
    if run_status == Workflow2Run.STATUS_REJECTED:
        return Workflow2IssuanceDecision.REJECT
    if run_status in WORKFLOW2_NEGATIVE_RUN_STATUSES:
        return Workflow2IssuanceDecision.FAIL
    return Workflow2IssuanceDecision.FAIL


def get_workflow2_run_detail_path(context: BaseRequestContext) -> str | None:
    """Return a workflow2 run detail path for the current request, if available."""
    outcome = get_workflow2_dispatch_outcome(context)
    if outcome is None or outcome.run is None:
        return None
    return f'/workflows2/runs/{outcome.run.id}/'
