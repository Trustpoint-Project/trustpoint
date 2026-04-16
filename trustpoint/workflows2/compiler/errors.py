"""Compiler-specific exceptions for Workflow 2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CompileError(Exception):
    """Describe a compile error with an optional source path and details."""

    message: str
    path: str = ''          # e.g. "workflow.steps.notify.subject"
    details: Any = None

    def __str__(self) -> str:
        """Return a human-readable error message."""
        if self.path:
            return f'{self.path}: {self.message}'
        return self.message
