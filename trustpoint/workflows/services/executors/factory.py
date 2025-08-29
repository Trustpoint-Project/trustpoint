"""Factory and base types for workflow node executors.

Provides:
    - AbstractNodeExecutor: common interface for node executors.
    - NodeExecutorFactory: registry-based factory to instantiate executors by node type.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:  # Application imports for type checking only.
    from workflows.models import WorkflowInstance
    from workflows.services.types import NodeResult


class AbstractNodeExecutor:
    """Base class for all node executors."""

    def execute(self, instance: WorkflowInstance, signal: str | None) -> NodeResult:
        """Execute this node.

        Args:
            instance: The workflow instance being advanced.
            signal: Optional external signal passed to the node.

        Returns:
            The result of executing the node.
        """
        return self.do_execute(instance, signal)

    def do_execute(  # pragma: no cover
        self, instance: WorkflowInstance, signal: str | None
    ) -> NodeResult:
        """Actual execution hook implemented by concrete executors.

        Args:
            instance: The workflow instance being advanced.
            signal: Optional external signal passed to the node.

        Returns:
            The result of executing the node.

        Raises:
            NotImplementedError: Always; subclasses must implement.
        """
        msg = 'Subclasses must implement do_execute().'
        raise NotImplementedError(msg)


class NodeExecutorFactory:
    """Registry-backed factory for node executors."""

    _registry: ClassVar[dict[str, type[AbstractNodeExecutor]]] = {}

    @classmethod
    def register(cls, node_type: str, executor_cls: type[AbstractNodeExecutor]) -> None:
        """Register an executor class for a node type.

        Args:
            node_type: Identifier of the node type.
            executor_cls: Concrete executor class to instantiate for this type.
        """
        cls._registry[node_type] = executor_cls

    @classmethod
    def create(cls, node_type: str) -> AbstractNodeExecutor:
        """Create an executor for the given node type.

        Args:
            node_type: Identifier of the node type.

        Returns:
            An instance of the registered executor class.

        Raises:
            ValueError: If no executor is registered for ``node_type``.
        """
        try:
            return cls._registry[node_type]()
        except KeyError as exc:
            msg = f'No executor registered for node type {node_type!r}'
            raise ValueError(msg) from exc
