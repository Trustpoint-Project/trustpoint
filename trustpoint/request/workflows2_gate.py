"""Helpers for interpreting Workflow 2 outcomes inside the request pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from workflows2.models import Workflow2Run

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext
    from workflows2.services.dispatch import DispatchOutcome


PENDING_RUN_STATUSES: set[str] = {
    Workflow2Run.STATUS_QUEUED,
    Workflow2Run.STATUS_RUNNING,
    Workflow2Run.STATUS_AWAITING,
    Workflow2Run.STATUS_PAUSED,
}

NEGATIVE_RUN_STATUSES: set[str] = {
    Workflow2Run.STATUS_REJECTED,
    Workflow2Run.STATUS_FAILED,
    Workflow2Run.STATUS_CANCELLED,
    Workflow2Run.STATUS_STOPPED,
}


def get_workflow2_outcome(context: BaseRequestContext) -> DispatchOutcome | None:
    """Return the Workflow 2 dispatch outcome stored on the request context."""
    outcome = getattr(context, 'workflow2_outcome', None)
    return cast('DispatchOutcome | None', outcome)


def workflow2_allows_certificate_issuance(context: BaseRequestContext) -> bool:
    """Return whether certificate issuance should continue for this request."""
    outcome = get_workflow2_outcome(context)
    if outcome is None:
        return True
    return str(outcome.run.status) == Workflow2Run.STATUS_SUCCEEDED


def workflow2_run_detail_path(context: BaseRequestContext) -> str | None:
    """Return a workflow2 run detail path for the current request, if available."""
    outcome = get_workflow2_outcome(context)
    if outcome is None or outcome.run is None:
        return None
    return f'/workflows2/runs/{outcome.run.id}/'
