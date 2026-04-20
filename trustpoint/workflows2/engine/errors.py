"""Execution-time exceptions for Workflow 2."""

from __future__ import annotations


class ExecutionError(RuntimeError):
    """Base class for Workflow 2 runtime failures."""



class StepExecutionError(ExecutionError):
    """Raise when a concrete workflow step fails during execution."""

    def __init__(self, step_id: str, message: str) -> None:
        """Initialize the error with the failing step identifier."""
        super().__init__(f'{step_id}: {message}')
        self.step_id = step_id
        self.message = message
