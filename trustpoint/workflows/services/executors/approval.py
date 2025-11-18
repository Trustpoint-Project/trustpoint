"""Approval step executor."""
from __future__ import annotations

from workflows.models import State, WorkflowInstance
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecutorResult


class ApprovalExecutor(AbstractStepExecutor):
    """First encounter (no signal) → WAITING (engine maps to AwaitingApproval).

    - On "Rejected" → REJECTED (terminal).
    - On "Approved":
        • If this is the last Approval step → APPROVED (engine will continue if more steps exist).
        • Otherwise → PASSED (engine continues).
    """

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> ExecutorResult:
        """Execute the approval step and return the resulting state.

        Args:
            instance: Workflow instance being processed.
            signal: External decision signal such as ``approve`` or ``reject``.

        Returns:
            ExecutorResult describing the new workflow state and step context.
        """
        # First visit (no signal) → WAITING
        if signal is None and instance.state is WorkflowInstance.STATE_RUNNING:
            return ExecutorResult(
                status=State.AWAITING,
                context={
                    'type': 'Approval',
                    'status': 'AwaitingApproval',
                    'error': None,
                    'outputs': {'AwaitingApproval': True},
                },
            )

        # Rejected → terminal
        if signal == 'reject':
            return ExecutorResult(
                status=State.REJECTED,
                context={
                    'type': 'Approval',
                    'status': 'rejected',
                    'error': None,
                    'outputs': {'decision': 'Rejected'},
                },
            )

        # Approved
        if signal == 'approve':
            if instance.is_last_approval_step():
                return ExecutorResult(
                    status=State.APPROVED,
                    context={
                        'type': 'Approval',
                        'status': 'approved',
                        'error': None,
                        'outputs': {'decision': 'Approved', 'last_approval': True},
                    },
                )
            return ExecutorResult(
                status=State.PASSED,
                context={
                    'type': 'Approval',
                    'status': 'passed',
                    'error': None,
                    'outputs': {'decision': 'Approved'},
                },
            )

        # Any other case → still waiting
        return ExecutorResult(
            status=State.AWAITING,
            context={
                'type': 'Approval',
                'status': 'AwaitingApproval',
                'error': None,
                'outputs': {'AwaitingApproval': True},
            },
        )
