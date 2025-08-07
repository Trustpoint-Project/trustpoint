from __future__ import annotations

from workflows.models import WorkflowInstance


class NodeExecutorFactory:
    """Registry of node‐type → executor class."""

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
        if executor_cls is None:
            raise ValueError(f'No executor registered for node type {node_type!r}')
        return executor_cls()


class AbstractNodeExecutor:
    """Template for node executors."""

    def execute(
        self,
        instance: WorkflowInstance,
        signal: str | None = None,
    ) -> tuple[str | None, str]:
        """Run this executor and return (next_step, next_state)."""
        return self.do_execute(instance, signal)

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        """Subclasses must implement their node’s behavior."""
        raise NotImplementedError


class ApprovalExecutor(AbstractNodeExecutor):
    """Handle Approval nodes: pause, then react to Approved/Rejected."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        # 1) first time we hit this node → wait for approval
        if (
            instance.state
            in {
                WorkflowInstance.STATE_STARTING,
                WorkflowInstance.STATE_RUNNING,
            }
            and signal is None
        ):
            return instance.current_step, WorkflowInstance.STATE_AWAITING

        # 2) rejected at any time → terminal
        if signal == 'Rejected':
            return None, WorkflowInstance.STATE_REJECTED

        # 3) approved → either move on or, if this was the last approval, mark approved
        if signal == 'Approved':
            if instance.is_last_approval_step():
                return None, WorkflowInstance.STATE_APPROVED
            next_id = instance.get_next_step()
            return next_id, WorkflowInstance.STATE_RUNNING

        # 4) any other case (shouldn’t really happen) → no-op
        return instance.current_step, instance.state


class IssueCertificateExecutor(AbstractNodeExecutor):
    """Immediately completes."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        return None, WorkflowInstance.STATE_COMPLETED


class ConditionExecutor(AbstractNodeExecutor):
    """Stub: evaluate condition, then choose branch or complete."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        # TODO: inspect instance.definition.definition for expression
        return None, instance.state


class EmailExecutor(AbstractNodeExecutor):
    """Stub: send email, then continue."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        # TODO: send your email
        return None, instance.state


class WebhookExecutor(AbstractNodeExecutor):
    """Stub: invoke HTTP, then continue."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        # TODO: call webhook
        return None, instance.state


class TimerExecutor(AbstractNodeExecutor):
    """Stub: check or schedule timer, then continue or await."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        # TODO: handle timer logic
        return None, instance.state


# Register built‐in executors
NodeExecutorFactory.register('Approval', ApprovalExecutor)
NodeExecutorFactory.register('IssueCertificate', IssueCertificateExecutor)
NodeExecutorFactory.register('Condition', ConditionExecutor)
NodeExecutorFactory.register('Email', EmailExecutor)
NodeExecutorFactory.register('Webhook', WebhookExecutor)
NodeExecutorFactory.register('Timer', TimerExecutor)
