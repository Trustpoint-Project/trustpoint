"""Aggregation helpers for enrollment requests."""
from __future__ import annotations

from django.db import transaction

from workflows.models import EnrollmentRequest, WorkflowInstance

TERMINAL_GOOD = {WorkflowInstance.STATE_APPROVED, WorkflowInstance.STATE_PASSED}
NONFINAL_ACTIVE = {WorkflowInstance.STATE_RUNNING, WorkflowInstance.STATE_AWAITING}


def recompute_request_state(req: EnrollmentRequest) -> None:
    """Aggregate instances → req.aggregated_state.

      - Rejected  if any instance is Rejected
      - Pending   if any instance is Starting/Running/AwaitingApproval
      - Ready     if all instances are Approved/Completed and there is at least one instance
    Note: We do NOT set Completed here; EST issuance will set Completed.
    """
    with transaction.atomic():
        req = EnrollmentRequest.objects.select_for_update().get(pk=req.pk)
        qs = req.instances.all()
        states = list(qs.values_list('state', flat=True))

        if not states:
            req.aggregated_state = EnrollmentRequest.STATE_PASSED
            req.save(update_fields=['aggregated_state'])
            return

        if any(s == WorkflowInstance.STATE_FAILED for s in states):
            req.aggregated_state = EnrollmentRequest.STATE_FAILED
            req.save(update_fields=['aggregated_state'])
            return

        if any(s == WorkflowInstance.STATE_REJECTED for s in states):
            req.aggregated_state = EnrollmentRequest.STATE_REJECTED
            req.save(update_fields=['aggregated_state'])
            return

        if any(s in NONFINAL_ACTIVE for s in states):
            req.aggregated_state = EnrollmentRequest.STATE_AWAITING
            req.save(update_fields=['aggregated_state'])
            return

        if all(s in TERMINAL_GOOD for s in states):
            req.aggregated_state = EnrollmentRequest.STATE_APPROVED
            req.save(update_fields=['aggregated_state'])
            return

        # Fallback: treat unknown combos as Failed
        req.aggregated_state = EnrollmentRequest.STATE_FAILED
        req.save(update_fields=['aggregated_state'])
