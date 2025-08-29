"""Approval executor for workflow nodes."""

from __future__ import annotations

from workflows.models import WorkflowInstance
from workflows.services.executors.factory import AbstractNodeExecutor
from workflows.services.types import ExecStatus, NodeResult


class ApprovalExecutor(AbstractNodeExecutor):
    """Implements approval semantics for workflow execution.

    - First encounter → WAITING (engine sets state=AwaitingApproval).
    - On "Rejected" → REJECTED (terminal).
    - On "Approved":
        • If this is the last Approval node in the workflow → APPROVED (terminal).
        • Otherwise → PASSED (engine continues to next node in the same call).
    """

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        """Execute the approval step.

        Args:
            instance: The workflow instance being evaluated.
            signal: External signal indicating approval or rejection.

        Returns:
            A NodeResult indicating the current approval outcome.
        """
        if signal is None and instance.state in {
            WorkflowInstance.STATE_STARTING,
            WorkflowInstance.STATE_RUNNING,
        }:
            return NodeResult(
                status=ExecStatus.WAITING,
                wait_state=WorkflowInstance.STATE_AWAITING,
                context={'awaiting': True},
            )

        if signal == 'Rejected':
            return NodeResult(status=ExecStatus.REJECTED)

        if signal == 'Approved':
            if instance.is_last_approval_step():
                return NodeResult(status=ExecStatus.APPROVED, context={'last_approval': True})
            return NodeResult(status=ExecStatus.PASSED, context={'approved': True})

        # Default: still waiting
        return NodeResult(status=ExecStatus.WAITING, wait_state=WorkflowInstance.STATE_AWAITING)
