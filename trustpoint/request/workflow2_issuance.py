"""Helpers for interpreting Workflow 2 outcomes during certificate issuance."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from cmp.models import CmpTransactionModel
from request.request_context import CmpBaseRequestContext
from workflows2.services.dispatch import WorkflowDispatchService
from workflows2.services.request_decision import Workflow2RequestDecision, resolve_request_decision

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext
    from workflows2.services.dispatch import DispatchOutcome

Workflow2IssuanceDecision = Workflow2RequestDecision


def get_workflow2_dispatch_outcome(context: BaseRequestContext) -> DispatchOutcome | None:
    """Return the Workflow 2 dispatch outcome stored on the request context."""
    outcome = getattr(context, 'workflow2_outcome', None)
    return cast('DispatchOutcome | None', outcome)


def get_workflow2_issuance_decision(context: BaseRequestContext) -> Workflow2IssuanceDecision:
    """Return the issuance decision implied by the current Workflow 2 outcome."""
    outcome = get_workflow2_dispatch_outcome(context)
    if outcome is None:
        return Workflow2IssuanceDecision.CONTINUE

    return Workflow2IssuanceDecision(resolve_request_decision(outcome.run).value)


def get_workflow2_run_detail_path(context: BaseRequestContext) -> str | None:
    """Return a workflow2 run detail path for the current request, if available."""
    outcome = get_workflow2_dispatch_outcome(context)
    if outcome is None or outcome.run is None:
        return None
    return f'/workflows2/runs/{outcome.run.id}/'


def release_delivered_workflow2_request(context: BaseRequestContext) -> None:
    """Release one request workflow run after the final requester response was built."""
    run_id = _resolve_delivered_workflow2_run_id(context)
    if run_id is None:
        return
    WorkflowDispatchService.release_run_idempotency(run_id=run_id)


def _resolve_delivered_workflow2_run_id(context: BaseRequestContext) -> str | None:
    """Return the workflows2 run ID whose idempotency key may now be released.

    For HTTP request/response protocols we only release successful request runs
    after the final requester-visible success response was built. CMP polling is
    slightly different: the final success may be produced from the persisted CMP
    transaction instead of the original request context, so the CMP transaction
    backend reference becomes the source of truth there.
    """
    outcome = get_workflow2_dispatch_outcome(context)
    if (
        outcome is not None
        and resolve_request_decision(outcome.run) == Workflow2RequestDecision.CONTINUE
    ):
        return str(outcome.run.id)

    if not isinstance(context, CmpBaseRequestContext):
        return None

    transaction = context.cmp_transaction
    if not isinstance(transaction, CmpTransactionModel):
        return None
    if context.http_response_content_type != 'application/pkixcmp':
        return None
    if transaction.status != CmpTransactionModel.Status.ISSUED:
        return None

    backend_reference = str(transaction.backend_reference or '').strip()
    return backend_reference or None
