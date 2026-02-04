# workflows2/compiler/errors.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CompileError(Exception):
    message: str
    path: str = ""          # e.g. "workflow.steps.notify.subject"
    details: Any = None

    def __str__(self) -> str:
        if self.path:
            return f"{self.path}: {self.message}"
        return self.message
