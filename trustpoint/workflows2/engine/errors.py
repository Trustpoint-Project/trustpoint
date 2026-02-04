# workflows2/engine/errors.py
from __future__ import annotations


class ExecutionError(RuntimeError):
    pass


class StepExecutionError(ExecutionError):
    def __init__(self, step_id: str, message: str) -> None:
        super().__init__(f"{step_id}: {message}")
        self.step_id = step_id
        self.message = message
