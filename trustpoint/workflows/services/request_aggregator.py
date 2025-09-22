from __future__ import annotations

from django.db import transaction

from workflows.models import EnrollmentRequest, WorkflowInstance

TERMINAL_GOOD = {WorkflowInstance.STATE_APPROVED, WorkflowInstance.STATE_COMPLETED}
NONFINAL_ACTIVE = {WorkflowInstance.STATE_STARTING, WorkflowInstance.STATE_RUNNING, WorkflowInstance.STATE_AWAITING}


def recompute_request_state(req: EnrollmentRequest) -> None:
    """Aggregate instances → req.aggregate_state.

      - Rejected  if any instance is Rejected
      - Pending   if any instance is Starting/Running/AwaitingApproval
      - Ready     if all instances are Approved/Completed and there is at least one instance
      - NoMatch   if there are no instances
    Note: We do NOT set Completed here; EST issuance will set Completed.
    """
    with transaction.atomic():
        req = EnrollmentRequest.objects.select_for_update().get(pk=req.pk)
        qs = req.instances.all()
        states = list(qs.values_list('state', flat=True))

        if not states:
            req.aggregate_state = EnrollmentRequest.STATE_NOMATCH
            req.save(update_fields=['aggregate_state'])
            return

        if any(s == WorkflowInstance.STATE_REJECTED for s in states):
            req.aggregate_state = EnrollmentRequest.STATE_REJECTED
            req.save(update_fields=['aggregate_state'])
            return

        if any(s in NONFINAL_ACTIVE for s in states):
            req.aggregate_state = EnrollmentRequest.STATE_PENDING
            req.save(update_fields=['aggregate_state'])
            return

        if all(s in TERMINAL_GOOD for s in states):
            req.aggregate_state = EnrollmentRequest.STATE_APPROVED
            req.save(update_fields=['aggregate_state'])
            return

        # Fallback: treat unknown combos as Pending
        req.aggregate_state = EnrollmentRequest.STATE_PENDING
        req.save(update_fields=['aggregate_state'])
