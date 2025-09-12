from __future__ import annotations

from workflows.models import WorkflowInstance
from workflows.services.executors.factory import AbstractNodeExecutor
from workflows.services.types import ExecStatus, NodeResult


class ApprovalExecutor(AbstractNodeExecutor):
    """First encounter (no signal) → WAITING (engine maps to AwaitingApproval).

    - On "Rejected" → REJECTED (terminal).
    - On "Approved":
        • If this is the last Approval node → APPROVED (engine will continue if more steps exist).
        • Otherwise → PASSED (engine continues).
    """

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        # First visit (no signal) → WAITING
        if signal is None and instance.state in {
            WorkflowInstance.STATE_STARTING,
            WorkflowInstance.STATE_RUNNING,
        }:
            return NodeResult(
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
            return NodeResult(
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
                return NodeResult(
                    status=ExecStatus.APPROVED,
                    context={
                        'type': 'Approval',
                        'ok': True,
                        'status': 'approved',
                        'error': None,
                        'outputs': {'decision': 'Approved', 'last_approval': True},
                    },
                )
            return NodeResult(
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
        return NodeResult(
            status=ExecStatus.WAITING,
            context={
                'type': 'Approval',
                'ok': False,
                'status': 'waiting',
                'error': None,
                'outputs': {'awaiting': True},
            },
        )
