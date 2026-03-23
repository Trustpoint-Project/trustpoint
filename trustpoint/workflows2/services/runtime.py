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

    Policy (Modified B):
      - Step exceptions => instance.status = FAILED (retryable), keep current_step
      - Failed is NOT treated as finalized in run aggregation (manual retry allowed)
      - Always persist a Workflow2StepRun row even on exception
    """

    def __init__(self, *, executor: WorkflowExecutor, max_steps_per_run: int = 200) -> None:
        self.executor = executor
        self.max_steps_per_run = max_steps_per_run

    @transaction.atomic
    def recompute_run_status(self, run: Any) -> None:
        self._recompute_run(run)

    @transaction.atomic
    def create_instance(
        self,
        *,
        definition: Workflow2Definition,
        event: dict[str, Any],
        initial_vars: dict[str, Any] | None = None,
        run: Any | None = None,
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
                Workflow2Instance.STATUS_CANCELLED,
                Workflow2Instance.STATUS_AWAITING,
                Workflow2Instance.STATUS_PAUSED,
            }:
                return instance

            if instance.current_step is None:
                instance.status = Workflow2Instance.STATUS_SUCCEEDED
                instance.save(update_fields=["status", "updated_at"])
                self._recompute_run_if_present(instance)
                return instance

            if steps >= self.max_steps_per_run:
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.save(update_fields=["status", "updated_at"])
                self._recompute_run_if_present(instance)
                return instance

            self.run_one_step(instance)
            steps += 1

    def run_one_step(self, instance: Workflow2Instance) -> StepResult:
        try:
            with transaction.atomic():
                instance = (
                    Workflow2Instance.objects.select_for_update()
                    .select_related("definition")
                    .get(id=instance.id)
                )

                if instance.status in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_CANCELLED,
                    Workflow2Instance.STATUS_AWAITING,
                    Workflow2Instance.STATUS_PAUSED,
                }:
                    raise ValueError("Instance is terminal/blocked; cannot run")

                if instance.current_step is None:
                    instance.status = Workflow2Instance.STATUS_SUCCEEDED
                    instance.save(update_fields=["status", "updated_at"])
                    self._recompute_run_if_present(instance)
                    return StepResult(
                        run=StepRun(
                            run_index=int(instance.run_count) + 1,
                            step_id="(end)",
                            step_type="end",
                            status="succeeded",
                            outcome=None,
                            next_step=None,
                            vars_delta={},
                            output=None,
                            error=None,
                            created_at=timezone.now(),
                        ),
                        terminal=True,
                    )

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
                    vars_delta=run.vars_delta or {},
                    output=run.output,
                    error=run.error,
                    created_at=timezone.now(),
                )

                instance.vars_json = ctx.vars
                instance.run_count = run_index

                if run.status == "awaiting":
                    self._ensure_approval(instance=instance, step_id=step_id)
                    instance.status = Workflow2Instance.STATUS_AWAITING
                    instance.current_step = step_id
                    instance.save(update_fields=["vars_json", "run_count", "status", "current_step", "updated_at"])
                    self._recompute_run_if_present(instance)
                    return StepResult(run=run, terminal=True)

                if run.next_step is None:
                    instance.status = Workflow2Instance.STATUS_SUCCEEDED
                    instance.current_step = None
                    instance.save(update_fields=["vars_json", "run_count", "status", "current_step", "updated_at"])
                    self._recompute_run_if_present(instance)
                    return StepResult(run=run, terminal=True)

                instance.status = Workflow2Instance.STATUS_RUNNING
                instance.current_step = run.next_step
                instance.save(update_fields=["vars_json", "run_count", "status", "current_step", "updated_at"])
                self._recompute_run_if_present(instance)
                return StepResult(run=run, terminal=False)

        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"

            with transaction.atomic():
                instance = (
                    Workflow2Instance.objects.select_for_update()
                    .select_related("definition")
                    .get(id=instance.id)
                )

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
                    vars_delta={},
                    output=None,
                    error=err,
                    created_at=timezone.now(),
                )

                instance.run_count = run_index
                instance.status = Workflow2Instance.STATUS_FAILED
                instance.save(update_fields=["run_count", "status", "updated_at"])

                self._recompute_run_if_present(instance)

            raise

    @transaction.atomic
    def resolve_approval(self, *, approval: Workflow2Approval, decision: str) -> None:
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be 'approved' or 'rejected'")

        approval = Workflow2Approval.objects.select_for_update().select_related("instance").get(id=approval.id)
        inst = Workflow2Instance.objects.select_for_update().select_related("definition").get(id=approval.instance_id)

        if inst.status != Workflow2Instance.STATUS_AWAITING:
            raise ValueError("Instance must be awaiting to resolve approval")

        if approval.status != Workflow2Approval.STATUS_PENDING:
            raise ValueError("Approval is already resolved")

        ir = inst.definition.ir_json
        wf = (ir or {}).get("workflow") or {}
        steps_map = wf.get("steps") or {}
        transitions = (wf.get("transitions") or {}).get(approval.step_id)
        if not isinstance(transitions, dict) or transitions.get("kind") != "by_outcome":
            raise ValueError("Approval step missing by_outcome transitions in IR")

        step = steps_map.get(approval.step_id)
        params = (step.get("params") or {}) if isinstance(step, dict) else {}
        selected_outcome = (
            params.get("approved_outcome")
            if decision == "approved"
            else params.get("rejected_outcome")
        )
        if not isinstance(selected_outcome, str) or not selected_outcome:
            raise ValueError(f"Approval step missing configured outcome for decision '{decision}'")

        outcome_map = transitions.get("map") or {}
        if not isinstance(outcome_map, dict):
            raise ValueError("Invalid outcome map")

        next_step = outcome_map.get(selected_outcome)
        if not isinstance(next_step, str) or not next_step:
            raise ValueError(f"No route for approval outcome '{selected_outcome}'")

        approval.status = (
            Workflow2Approval.STATUS_APPROVED
            if decision == "approved"
            else Workflow2Approval.STATUS_REJECTED
        )
        approval.decided_at = timezone.now()
        approval.save(update_fields=["status", "decided_at"])

        run_index = int(inst.run_count) + 1
        terminal_reject = next_step == "$reject"
        terminal_end = next_step == "$end"
        next_step_id = None if terminal_end or terminal_reject else next_step
        step_run_status = (
            "rejected"
            if terminal_reject
            else "succeeded"
            if terminal_end
            else "continued"
        )

        Workflow2StepRun.objects.create(
            instance=inst,
            run_index=run_index,
            step_id=approval.step_id,
            step_type="approval",
            status=step_run_status,
            outcome=selected_outcome,
            next_step=next_step_id,
            vars_delta={},
            output={
                "decision": decision,
                "selected_outcome": selected_outcome,
            },
            error=None,
            created_at=timezone.now(),
        )

        inst.run_count = run_index
        if terminal_reject:
            inst.status = Workflow2Instance.STATUS_REJECTED
            inst.current_step = None
        elif terminal_end:
            inst.status = Workflow2Instance.STATUS_SUCCEEDED
            inst.current_step = None
        else:
            inst.status = Workflow2Instance.STATUS_RUNNING
            inst.current_step = next_step_id

        inst.save(update_fields=["run_count", "status", "current_step", "updated_at"])
        self._recompute_run_if_present(inst)

    def _ensure_approval(self, *, instance: Workflow2Instance, step_id: str) -> Workflow2Approval:
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
            defaults={"status": Workflow2Approval.STATUS_PENDING, "expires_at": expires_at},
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
        from workflows2.models import Workflow2Instance  # noqa: WPS433

        insts = list(Workflow2Instance.objects.filter(run=run).only("status"))
        statuses = [i.status for i in insts]
        if not statuses:
            return

        def _has(s: str) -> bool:
            return s in statuses

        # IMPORTANT: include PAUSED, and do NOT finalize FAILED/PAUSED/AWAITING
        if _has(Workflow2Instance.STATUS_REJECTED):
            run.status = "rejected"
        elif _has(Workflow2Instance.STATUS_PAUSED):
            run.status = "paused"
        elif _has(Workflow2Instance.STATUS_FAILED):
            run.status = "failed"
        elif _has(Workflow2Instance.STATUS_AWAITING):
            run.status = "awaiting"
        elif _has(Workflow2Instance.STATUS_RUNNING):
            run.status = "running"
        elif _has(Workflow2Instance.STATUS_QUEUED):
            run.status = "queued"
        else:
            run.status = "succeeded"

        no_match = getattr(run, "STATUS_NO_MATCH", None)
        terminal_statuses = {"succeeded", "rejected", "cancelled", "stopped"}
        if isinstance(no_match, str) and no_match:
            terminal_statuses.add(no_match)

        run.finalized = run.status in terminal_statuses
        run.save(update_fields=["status", "finalized", "updated_at"])
