# workflows2/engine/types.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal


StepStatus = Literal["ok", "failed", "stopped", "awaiting", "succeeded", "rejected"]
RunStatus = Literal["ok", "failed", "stopped", "awaiting", "succeeded", "rejected"]


@dataclass
class StepRun:
    run_index: int
    step_id: str
    step_type: str
    status: StepStatus
    outcome: str | None
    next_step: str | None
    vars_delta: dict[str, Any]
    output: dict[str, Any] | None
    error: str | None
    created_at: datetime


@dataclass
class ExecutionResult:
    status: RunStatus
    start_step: str
    end_step: str | None
    vars: dict[str, Any]
    runs: list[StepRun]
