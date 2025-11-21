"""Factory and base types for workflow step executors."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:  # Application imports for type checking only.
    from workflows.models import WorkflowInstance
    from workflows.services.types import ExecutorResult


class AbstractStepExecutor:
    """Base class for all step executors."""

    def execute(self, instance: WorkflowInstance, signal: str | None) -> ExecutorResult:
        """Execute this step.

        Args:
            instance: The workflow instance being advanced.
            signal: Optional external signal passed to the step.

        Returns:
            The result of executing the step.
        """
        return self.do_execute(instance, signal)

    def do_execute(self, instance: WorkflowInstance, signal: str | None) -> ExecutorResult:
        """Actual execution hook implemented by concrete executors.

        Args:
            instance: The workflow instance being advanced.
            signal: Optional external signal passed to the step.

        Returns:
            The result of executing the step.

        Raises:
            NotImplementedError: Always; subclasses must implement.
        """
        msg = 'Subclasses must implement do_execute().'
        raise NotImplementedError(msg)


class StepExecutorFactory:
    """Registry-backed factory for step executors."""

    _registry: ClassVar[dict[str, type[AbstractStepExecutor]]] = {}

    @classmethod
    def register(cls, step_type: str, executor_cls: type[AbstractStepExecutor]) -> None:
        """Register an executor class for a step type.

        Args:
            step_type: Identifier of the step type.
            executor_cls: Concrete executor class to instantiate for this type.
        """
        cls._registry[step_type] = executor_cls

    @classmethod
    def create(cls, step_type: str) -> AbstractStepExecutor:
        """Create an executor for the given step type.

        Args:
            step_type: Identifier of the step type.

        Returns:
            An instance of the registered executor class.

        Raises:
            ValueError: If no executor is registered for ``step_type``.
        """
        try:
            return cls._registry[step_type]()
        except KeyError as exc:
            msg = f'No executor registered for step type {step_type!r}'
            raise ValueError(msg) from exc

    @classmethod
    def registered_types(cls) -> set[str]:
        """Return the set of registered step type identifiers."""
        return set(cls._registry.keys())
