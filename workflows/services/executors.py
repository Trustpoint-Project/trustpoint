from __future__ import annotations

from typing import Any, Optional, Tuple

from workflows.models import WorkflowInstance


class NodeExecutorFactory:
    """Factory Method: map node types to their executor classes."""
    _registry: dict[str, type[AbstractNodeExecutor]] = {}

    @classmethod
    def register(
        cls,
        node_type: str,
        executor_cls: type[AbstractNodeExecutor],
    ) -> None:
        cls._registry[node_type] = executor_cls

    @classmethod
    def create(cls, node_type: str) -> AbstractNodeExecutor:
        executor_cls = cls._registry.get(node_type)
        if not executor_cls:
            raise ValueError(f'No executor registered for node type {node_type!r}')
        return executor_cls()


class AbstractNodeExecutor:
    """Template Method: wrap common pre/post logic around do_execute()."""

    def execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str] = None,
    ) -> tuple[Optional[str], str]:
        """Run this executor and return (next_node, next_state)."""
        # (pre‑execution hooks could go here)
        next_node, next_state = self.do_execute(instance, signal)
        # (post‑execution hooks could go here)
        return next_node, next_state

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str],
    ) -> tuple[Optional[str], str]:
        """Subclasses must implement their node’s behavior."""
        raise NotImplementedError


class ApprovalExecutor(AbstractNodeExecutor):
    """Handles Approval nodes: send email, wait for, and process approval."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str],
    ) -> tuple[Optional[str], str]:
        transitions = instance.definition.definition['transitions']

        # 1) First arrival: move to AwaitingApproval
        if instance.state == WorkflowInstance.STATE_STARTED:
            # TODO: send your approval email here
            return instance.current_node, WorkflowInstance.STATE_AWAITING

        # 2) On 'Approved' or fallback to 'next'
        if signal == 'Approved':
            # pick either an explicit Approved edge, or fallback to next
            approved_transition = next(
                (
                    t for t in transitions
                    if t['from'] == instance.current_node
                    and t.get('on') in ('Approved', 'next')
                ),
                None,
            )
            if approved_transition:
                return approved_transition['to'], WorkflowInstance.STATE_STARTED
            # no explicit path → complete?
            return None, WorkflowInstance.STATE_COMPLETED

        # 3) On 'Rejected'
        if signal == 'Rejected':
            return None, WorkflowInstance.STATE_REJECTED

        # 4) Any other signal: stay put
        return instance.current_node, instance.state

class IssueCertificateExecutor(AbstractNodeExecutor):
    """Handles IssueCertificate nodes: call PKI logic to issue the cert."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str],
    ) -> tuple[Optional[str], str]:
        # call into your existing PKI issue logic here...
        return None, WorkflowInstance.STATE_COMPLETED


# Roadmap: register additional executors
class ConditionExecutor(AbstractNodeExecutor):
    """Evaluate a condition and branch accordingly."""
    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str],
    ) -> tuple[Optional[str], str]:
        # implement condition logic...
        return None, instance.state


class EmailExecutor(AbstractNodeExecutor):
    """Send templated email notifications."""
    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str],
    ) -> tuple[Optional[str], str]:
        # implement email logic...
        return None, instance.state


class WebhookExecutor(AbstractNodeExecutor):
    """Invoke an external HTTP endpoint."""
    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str],
    ) -> tuple[Optional[str], str]:
        # implement webhook logic...
        return None, instance.state


class TimerExecutor(AbstractNodeExecutor):
    """Schedule or await a timer event."""
    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: Optional[str],
    ) -> tuple[Optional[str], str]:
        # implement timer logic...
        return None, instance.state


# Register all executors
NodeExecutorFactory.register('Approval', ApprovalExecutor)
NodeExecutorFactory.register('IssueCertificate', IssueCertificateExecutor)
NodeExecutorFactory.register('Condition', ConditionExecutor)
NodeExecutorFactory.register('Email', EmailExecutor)
NodeExecutorFactory.register('Webhook', WebhookExecutor)
NodeExecutorFactory.register('Timer', TimerExecutor)
