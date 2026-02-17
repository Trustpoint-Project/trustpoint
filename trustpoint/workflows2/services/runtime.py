# workflows2/services/runtime.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.utils import timezone

from workflows2.engine.context import RuntimeContext
from workflows2.engine.executor import WorkflowExecutor
from workflows2.engine.types import StepRun
from workflows2.models import (
    Workflow2Approval,
    Workflow2Definition,
    Workflow2Instance,
    Workflow2StepRun,
)


@dataclass(frozen=True)
class StepResult:
    run: StepRun
    terminal: bool


class WorkflowRuntimeService:
    """
    Crash-resumable runtime (DB checkpointing).

    Contract:
      - Persist after EVERY executed step.
      - Instance.current_step always points to the NEXT step to execute.
        (or None when terminal, current step when awaiting)
    """

    def __init__(self, *, executor: WorkflowExecutor, max_steps_per_run: int = 200) -> None:
        self.executor = executor
        self.max_steps_per_run = max_steps_per_run

    # ------------------ public API expected by dispatch ------------------ #

    @transaction.atomic
    def recompute_run_status(self, run: Any) -> None:
        """
        Public method expected by services/dispatch.py.
        """
        self._recompute_run(run)

    # ------------------ instance lifecycle ------------------ #

    @transaction.atomic
    def create_instance(
        self,
        *,
        definition: Workflow2Definition,
        event: dict[str, Any],
        initial_vars: dict[str, Any] | None = None,
        run: Any | None = None,  # Workflow2Run
    ) -> Workflow2Instance:
        wf = (definition.ir_json or {}).get("workflow") or {}
        start = wf.get("start")
        if not isinstance(start, str) or not start:
            raise ValueError("Definition IR missing workflow.start")

        kwargs: dict[str, Any] = {
            "definition": definition,
            "event_json": event,
            "vars_json": initial_vars or {},
            "status": Workflow2Instance.STATUS_QUEUED,
            "current_step": start,
            "run_count": 0,
        }
        if run is not None:
            kwargs["run"] = run

        inst = Workflow2Instance.objects.create(**kwargs)
        self._recompute_run_if_present(inst)
        return inst

    def run_instance(self, instance: Workflow2Instance) -> Workflow2Instance:
        steps = 0
        while True:
            instance.refresh_from_db()
            if instance.status in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_REJECTED,
                Workflow2Instance.STATUS_FAILED,
                Workflow2Instance.STATUS_STOPPED,
                Workflow2Instance.STATUS_CANCELLED,
                Workflow2Instance.STATUS_AWAITING,
            }:
                return instance

            if instance.current_step is None:
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.save(update_fields=["status", "updated_at"])
                self._recompute_run_if_present(instance)
                return instance

            if steps >= self.max_steps_per_run:
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.save(update_fields=["status", "updated_at"])
                self._recompute_run_if_present(instance)
                return instance

            # this will raise on failure (and device create should fail)
            self.run_one_step(instance)
            steps += 1

    def run_one_step(self, instance: Workflow2Instance) -> StepResult:
        """
        NOTE:
        We intentionally DO NOT use @transaction.atomic on this function anymore.

        Reason:
          If the executor raises (e.g. SSLError), we still must commit a failure checkpoint
          (Workflow2StepRun + instance FAILED). If the exception escapes an atomic block,
          Django rolls back everything, leaving status QUEUED forever.
        """

        # ---------- Phase 1: attempt execution inside an atomic transaction ----------
        try:
            with transaction.atomic():
                instance = (
                    Workflow2Instance.objects
                    .select_for_update()
                    .select_related("definition")
                    .get(id=instance.id)
                )

                if instance.status in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
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

                terminal = False

                if run.status == "succeeded":
                    instance.status = Workflow2Instance.STATUS_SUCCEEDED
                    instance.current_step = None
                    terminal = True

                elif run.status == "rejected":
                    instance.status = Workflow2Instance.STATUS_REJECTED
                    instance.current_step = None
                    terminal = True

                elif run.status == "failed":
                    instance.status = Workflow2Instance.STATUS_FAILED
                    instance.current_step = None
                    terminal = True

                elif run.status == "stopped":
                    instance.status = Workflow2Instance.STATUS_STOPPED
                    instance.current_step = None
                    terminal = True

                elif run.status == "awaiting":
                    self._ensure_approval(instance=instance, step_id=step_id)
                    instance.status = Workflow2Instance.STATUS_AWAITING
                    instance.current_step = step_id
                    terminal = True

                else:
                    instance.status = Workflow2Instance.STATUS_RUNNING
                    instance.current_step = run.next_step
                    terminal = False

                instance.save(update_fields=["vars_json", "run_count", "status", "current_step", "updated_at"])
                self._recompute_run_if_present(instance)

                return StepResult(run=run, terminal=terminal)

        except Exception as e:  # noqa: BLE001
            # ---------- Phase 2: persist failure checkpoint in a NEW atomic transaction ----------
            err = f"{type(e).__name__}: {e}"

            with transaction.atomic():
                instance = (
                    Workflow2Instance.objects
                    .select_for_update()
                    .select_related("definition")
                    .get(id=instance.id)
                )

                # Determine step_id for reporting
                ir = instance.definition.ir_json if instance.definition_id else {}
                wf = (ir or {}).get("workflow") or {}
                steps_map = wf.get("steps") or {}

                step_id = instance.current_step or "unknown"
                step = steps_map.get(step_id) if isinstance(steps_map, dict) else None
                step_type = "unknown"
                if isinstance(step, dict):
                    step_type = str(step.get("type") or "unknown")

                run_index = int(instance.run_count) + 1

                Workflow2StepRun.objects.create(
                    instance=instance,
                    run_index=run_index,
                    step_id=step_id,
                    step_type=step_type,
                    status="failed",
                    outcome=None,
                    next_step=None,
                    vars_delta=None,
                    output=None,
                    error=err,
                    created_at=timezone.now(),
                )

                instance.run_count = run_index
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.current_step = None
                instance.save(update_fields=["run_count", "status", "current_step", "updated_at"])

                self._recompute_run_if_present(instance)

            # device create should fail -> re-raise AFTER failure checkpoint committed
            raise

    @transaction.atomic
    def resolve_approval(self, *, approval: Workflow2Approval, decision: str) -> None:
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be 'approved' or 'rejected'")

        approval = Workflow2Approval.objects.select_for_update().select_related("instance").get(id=approval.id)
        inst = Workflow2Instance.objects.select_for_update().select_related("definition").get(id=approval.instance_id)

        if inst.status != Workflow2Instance.STATUS_AWAITING:
            raise ValueError("Instance must be awaiting to resolve approval")

        ir = inst.definition.ir_json
        wf = (ir or {}).get("workflow") or {}
        transitions = (wf.get("transitions") or {}).get(approval.step_id)

        if not isinstance(transitions, dict) or transitions.get("kind") != "by_outcome":
            raise ValueError("Approval step missing by_outcome transitions in IR")

        outcome_map = transitions.get("map") or {}
        if not isinstance(outcome_map, dict):
            raise ValueError("Invalid outcome map")

        next_step = outcome_map.get(decision)
        if not isinstance(next_step, str) or not next_step:
            raise ValueError(f"No route for approval decision '{decision}'")

        approval.status = (
            Workflow2Approval.STATUS_APPROVED if decision == "approved" else Workflow2Approval.STATUS_REJECTED
        )
        if hasattr(approval, "decision"):
            setattr(approval, "decision", decision)
        if hasattr(approval, "decided_at"):
            setattr(approval, "decided_at", timezone.now())
        approval.save()

        run_index = int(inst.run_count) + 1
        Workflow2StepRun.objects.create(
            instance=inst,
            run_index=run_index,
            step_id=approval.step_id,
            step_type="approval",
            status="continued",
            outcome=decision,
            next_step=next_step,
            vars_delta=None,
            output={"decision": decision},
            error=None,
            created_at=timezone.now(),
        )

        inst.run_count = run_index
        inst.status = Workflow2Instance.STATUS_RUNNING
        inst.current_step = next_step
        inst.save(update_fields=["run_count", "status", "current_step", "updated_at"])

        self._recompute_run_if_present(inst)

    # ------------------ helpers ------------------ #

    def _ensure_approval(self, *, instance: Workflow2Instance, step_id: str) -> Workflow2Approval:
        """
        Create approval row if missing.
        """
        ir = instance.definition.ir_json
        wf = (ir or {}).get("workflow") or {}
        steps_map = wf.get("steps") or {}
        step = steps_map.get(step_id) or {}
        params = (step.get("params") or {}) if isinstance(step, dict) else {}

        timeout_seconds = params.get("timeout_seconds", None)
        expires_at = None
        if isinstance(timeout_seconds, int) and timeout_seconds > 0:
            expires_at = timezone.now() + timezone.timedelta(seconds=timeout_seconds)

        obj, _ = Workflow2Approval.objects.get_or_create(
            instance=instance,
            step_id=step_id,
            defaults={
                "status": Workflow2Approval.STATUS_PENDING,
                "expires_at": expires_at,
            },
        )
        return obj

    def _recompute_run_if_present(self, instance: Workflow2Instance) -> None:
        run_id = getattr(instance, "run_id", None)
        if not run_id:
            return
        from workflows2.models import Workflow2Run  # noqa: WPS433

        run = Workflow2Run.objects.select_for_update().get(id=run_id)
        self._recompute_run(run)

    @staticmethod
    def _recompute_run(run: Any) -> None:
        """
        Deterministic aggregation over child instances.

        Priority:
          REJECTED > FAILED > STOPPED > PAUSED > AWAITING > RUNNING > QUEUED > SUCCEEDED
        """
        from workflows2.models import Workflow2Instance  # noqa: WPS433

        insts = list(Workflow2Instance.objects.filter(run=run).only("status"))
        statuses = [i.status for i in insts]

        if not statuses:
            return

        def _has(s: str) -> bool:
            return s in statuses

        if _has(Workflow2Instance.STATUS_REJECTED):
            run.status = run.STATUS_REJECTED
        elif _has(Workflow2Instance.STATUS_FAILED):
            run.status = run.STATUS_FAILED
        elif _has(Workflow2Instance.STATUS_STOPPED):
            run.status = run.STATUS_STOPPED
        elif _has(Workflow2Instance.STATUS_PAUSED):
            run.status = run.STATUS_PAUSED
        elif _has(Workflow2Instance.STATUS_AWAITING):
            run.status = run.STATUS_AWAITING
        elif _has(Workflow2Instance.STATUS_RUNNING):
            run.status = run.STATUS_RUNNING
        elif _has(Workflow2Instance.STATUS_QUEUED):
            run.status = run.STATUS_QUEUED
        else:
            run.status = run.STATUS_SUCCEEDED

        run.save(update_fields=["status", "updated_at"])
