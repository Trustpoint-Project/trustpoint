from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ExecStatus(Enum):
    """Execution outcomes reported by executors to the engine."""
    PASSED = 'PASSED'
    WAITING = 'WAITING'
    APPROVED = 'APPROVED'
    REJECTED = 'REJECTED'
    COMPLETED = 'COMPLETED'
    FAIL = 'FAIL'


@dataclass(frozen=True)
class NodeResult:
    """Result returned by a node executor.

    Attributes:
        status: Execution status guiding engine behavior.
        context: Optional structured data to persist for this step (will be compacted).
        vars: Optional nested dict to merge into the instance-global ctx.vars (stored at step_contexts["$vars"]).
    """
    status: ExecStatus
    context: dict[str, Any] | None = None
    vars: dict[str, Any] | None = None
