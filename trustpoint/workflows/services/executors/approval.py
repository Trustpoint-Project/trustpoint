"""Approval step executor."""

from __future__ import annotations

from workflows.models import State, WorkflowInstance
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecutorResult, StepContext


class ApprovalExecutor(AbstractStepExecutor):
    """Approval step executor.

    Semantics:
    - If no signal is provided -> AWAITING (engine will keep the same current_step).
    - On "reject" -> REJECTED (terminal).
    - On "approve":
        * If this is the last Approval step -> APPROVED.
        * Otherwise -> PASSED (engine advances to next step).
    """

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> ExecutorResult:
        """Execute the approval step and return the resulting state."""
        if signal is None:
            return ExecutorResult(
                status=State.AWAITING,
                context=StepContext(
                    step_type='Approval',
                    step_status='AwaitingApproval',
                    error=None,
                    outputs={'AwaitingApproval': True},
                ),
            )

        if signal == 'reject':
            return ExecutorResult(
                status=State.REJECTED,
                context=StepContext(
                    step_type='Approval',
                    step_status='rejected',
                    error=None,
                    outputs={'decision': 'Rejected'},
                ),
            )

        if signal == 'approve':
            if instance.is_last_approval_step():
                return ExecutorResult(
                    status=State.APPROVED,
                    context=StepContext(
                        step_type='Approval',
                        step_status='approved',
                        error=None,
                        outputs={'decision': 'Approved', 'last_approval': True},
                    ),
                )
            return ExecutorResult(
                status=State.PASSED,
                context=StepContext(
                    step_type='Approval',
                    step_status='passed',
                    error=None,
                    outputs={'decision': 'Approved'},
                ),
            )

        # Any other signal -> remain waiting.
        return ExecutorResult(
            status=State.AWAITING,
            context=StepContext(
                step_type='Approval',
                step_status='AwaitingApproval',
                error=None,
                outputs={'AwaitingApproval': True},
            ),
        )
