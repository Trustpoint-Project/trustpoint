"""Types and results for workflow executors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from workflows.models import State


@dataclass(frozen=True)
class ExecutorResult:
    """Result returned by a step executor.

    Attributes:
        status: Workflow state guiding engine behavior.
        context: Optional structured data to persist for this step (will be compacted).
        vars: Optional nested dict to merge into the instance-global ctx.vars
              (stored under step_contexts["$vars"]).
    """
    status: State
    context: dict[str, Any] | None = None
    vars: dict[str, Any] | None = None
