"""Runtime context objects used while executing Workflow 2 steps."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RuntimeContext:
    """Carry the event payload and workflow vars for expression evaluation."""

    event: dict[str, Any]
    vars: dict[str, Any]
