from __future__ import annotations

from workflows.models import WorkflowInstance
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecStatus, ExecutorResult


class ApprovalExecutor(AbstractStepExecutor):
    """First encounter (no signal) → WAITING (engine maps to AwaitingApproval).

    - On "Rejected" → REJECTED (terminal).
    - On "Approved":
        • If this is the last Approval step → APPROVED (engine will continue if more steps exist).
        • Otherwise → PASSED (engine continues).
    """

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> ExecutorResult:
        # First visit (no signal) → WAITING
        if signal is None and instance.state is WorkflowInstance.STATE_RUNNING:
            return ExecutorResult(
                status=ExecStatus.WAITING,
                context={
                    'type': 'Approval',
                    'ok': False,
                    'status': 'waiting',
                    'error': None,
                    'outputs': {'awaiting': True},
                },
            )

        # Rejected → terminal
        if signal == 'Rejected':
            return ExecutorResult(
                status=ExecStatus.REJECTED,
                context={
                    'type': 'Approval',
                    'ok': False,
                    'status': 'rejected',
                    'error': None,
                    'outputs': {'decision': 'Rejected'},
                },
            )

        # Approved
        if signal == 'Approved':
            if instance.is_last_approval_step():
                return ExecutorResult(
                    status=ExecStatus.APPROVED,
                    context={
                        'type': 'Approval',
                        'ok': True,
                        'status': 'approved',
                        'error': None,
                        'outputs': {'decision': 'Approved', 'last_approval': True},
                    },
                )
            return ExecutorResult(
                status=ExecStatus.PASSED,
                context={
                    'type': 'Approval',
                    'ok': True,
                    'status': 'passed',
                    'error': None,
                    'outputs': {'decision': 'Approved'},
                },
            )

        # Any other case → still waiting
        return ExecutorResult(
            status=ExecStatus.WAITING,
            context={
                'type': 'Approval',
                'ok': False,
                'status': 'waiting',
                'error': None,
                'outputs': {'awaiting': True},
            },
        )
