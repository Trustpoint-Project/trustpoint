# workflows2/services/runtime.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.utils import timezone

from workflows2.engine.context import RuntimeContext
from workflows2.engine.executor import WorkflowExecutor
from workflows2.engine.types import StepRun
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2StepRun


@dataclass(frozen=True)
class StepResult:
    run: StepRun
    terminal: bool


class WorkflowRuntimeService:
    """
    Crash-resumable runtime.

    Contract:
      - Persist after EVERY executed step.
      - Instance.current_step always points to the NEXT step to execute.
        (or None when terminal/awaiting)
    """

    def __init__(self, *, executor: WorkflowExecutor, max_steps_per_run: int = 200) -> None:
        self.executor = executor
        self.max_steps_per_run = max_steps_per_run

    @transaction.atomic
    def create_instance(
        self,
        *,
        definition: Workflow2Definition,
        event: dict[str, Any],
        initial_vars: dict[str, Any] | None = None,
    ) -> Workflow2Instance:
        wf = (definition.ir_json or {}).get("workflow") or {}
        start = wf.get("start")
        if not isinstance(start, str) or not start:
            raise ValueError("Definition IR missing workflow.start")

        return Workflow2Instance.objects.create(
            definition=definition,
            event_json=event,
            vars_json=initial_vars or {},
            status=Workflow2Instance.STATUS_QUEUED,
            current_step=start,
            run_count=0,
        )

    def run_instance(self, instance: Workflow2Instance) -> Workflow2Instance:
        """
        Convenience for SYNC mode and tests:
        Run until terminal/awaiting, but still via step-by-step checkpointing.

        NOTE: Each step is its own transaction via run_one_step().
        """
        steps = 0
        while True:
            instance.refresh_from_db()
            if instance.status in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_FAILED,
                Workflow2Instance.STATUS_STOPPED,
                Workflow2Instance.STATUS_CANCELLED,
                Workflow2Instance.STATUS_AWAITING,
            }:
                return instance

            if instance.current_step is None:
                # inconsistent state: "running" but no next step
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.save(update_fields=["status", "updated_at"])
                return instance

            if steps >= self.max_steps_per_run:
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.save(update_fields=["status", "updated_at"])
                return instance

            self.run_one_step(instance)
            steps += 1

    @transaction.atomic
    def run_one_step(self, instance: Workflow2Instance) -> StepResult:
        """
        Execute exactly ONE step pointed to by instance.current_step,
        persist StepRun + instance checkpoint, and return.
        """
        if instance.status in {
            Workflow2Instance.STATUS_SUCCEEDED,
            Workflow2Instance.STATUS_FAILED,
            Workflow2Instance.STATUS_STOPPED,
            Workflow2Instance.STATUS_CANCELLED,
        }:
            raise ValueError("Instance is terminal; cannot run")

        if instance.current_step is None:
            raise ValueError("Instance has no current_step")

        ir = instance.definition.ir_json
        wf = (ir or {}).get("workflow") or {}
        steps_map = wf.get("steps") or {}
        transitions = wf.get("transitions") or {}

        step_id = instance.current_step
        step = steps_map.get(step_id)
        if not isinstance(step, dict):
            raise ValueError(f"Missing step definition: {step_id}")

        ctx = RuntimeContext(event=instance.event_json, vars=dict(instance.vars_json))
        run_index = int(instance.run_count) + 1

        run = self.executor.execute_single_step(
            ir=ir,
            step_id=step_id,
            run_index=run_index,
            ctx=ctx,
            transitions=transitions.get(step_id),
        )

        Workflow2StepRun.objects.create(
            instance=instance,
            run_index=run.run_index,
            step_id=run.step_id,
            step_type=run.step_type,
            status=run.status,
            outcome=run.outcome,
            next_step=run.next_step,
            vars_delta=run.vars_delta,
            output=run.output,
            error=run.error,
            created_at=timezone.now(),
        )

        instance.vars_json = ctx.vars
        instance.run_count = run_index

        # Terminal / awaiting / continue
        if run.status == "succeeded":
            instance.status = Workflow2Instance.STATUS_SUCCEEDED
            instance.current_step = None
            terminal = True
        elif run.status == "failed":
            instance.status = Workflow2Instance.STATUS_FAILED
            instance.current_step = None
            terminal = True
        elif run.status == "awaiting":
            instance.status = Workflow2Instance.STATUS_AWAITING
            instance.current_step = None
            terminal = True
        elif run.status == "stopped":
            instance.status = Workflow2Instance.STATUS_STOPPED
            instance.current_step = None
            terminal = True
        else:
            instance.status = Workflow2Instance.STATUS_RUNNING
            instance.current_step = run.next_step
            terminal = False

        instance.save(update_fields=["vars_json", "run_count", "status", "current_step", "updated_at"])
        return StepResult(run=run, terminal=terminal)
