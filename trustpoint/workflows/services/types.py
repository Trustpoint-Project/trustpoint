"""Types used by the workflows services layer.

Defines execution status values for workflow nodes and the result object
returned by node executors.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ExecStatus(Enum):
    """Enumeration of possible execution outcomes for a workflow node."""

    PASSED = 'PASSED'  # Node succeeded → advance to next node in this call.
    WAITING = 'WAITING'  # Pause engine; external signal required to resume.
    APPROVED = 'APPROVED'  # Terminal “approved” (e.g., EST immediate issuance).
    REJECTED = 'REJECTED'  # Terminal rejection.
    COMPLETED = 'COMPLETED'  # Run completed explicitly by executor.
    FAIL = 'FAIL'  # Node failed → engine marks instance FAILED.


@dataclass(frozen=True)
class NodeResult:
    """Result returned by a workflow node executor.

    Attributes:
        status: Outcome of the node execution.
        wait_state: When status is WAITING, the engine will set
            ``instance.state`` to this value if provided.
        context: Optional per-node context to store on the instance
            (e.g., ``step_contexts[current_step]``).
    """

    status: ExecStatus
    wait_state: str | None = None
    context: dict[str, Any] | None = None
