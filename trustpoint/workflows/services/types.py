"""Types and results for workflow executors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

    from workflows.models import State


JsonDict = dict[str, Any]


@dataclass(frozen=True)
class StepContext:
    """Canonical, JSON-serializable per-step context persisted by the engine.

    This structure is stored under:
        instance.step_contexts[str(instance.current_step)]

    Fields:
        step_type: Human-readable step type (e.g. "Email", "Webhook", "Approval").
        step_status: Step-local status (string). This is not the workflow State.
        error: Optional error message (string) if the step failed.
        outputs: Step-specific outputs. Must be JSON-serializable.

    Notes:
        - Keep outputs stable: prefer adding fields over changing meanings.
        - Keep error None on success.
    """

    step_type: str
    step_status: str
    error: str | None = None
    outputs: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Convert to dict for JSONField storage."""
        return {
            'type': self.step_type,
            'status': self.step_status,
            'error': self.error,
            'outputs': self.outputs,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StepContext:
        """Parse StepContext from a dict (defensive; primarily for tests)."""
        return cls(
            step_type=str(raw.get('type') or ''),
            step_status=str(raw.get('status') or ''),
            error=(None if raw.get('error') is None else str(raw.get('error'))),
            outputs=dict(raw.get('outputs') or {}),
        )


@dataclass(frozen=True)
class ExecutorResult:
    """Result returned by a step executor.

    Attributes:
        status: Workflow state guiding engine behavior.
        context: Optional StepContext to persist for this step.
        vars: Optional nested dict to merge into the instance-global ctx.vars
              (stored under step_contexts["$vars"]).
    """

    status: State
    context: StepContext | None = None
    vars: JsonDict | None = None
