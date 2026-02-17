# workflows2/services/dispatch.py
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job, Workflow2Run, Workflow2WorkerHeartbeat
from workflows2.services.runtime import WorkflowRuntimeService

# DB config (your singleton)
from management.models import WorkflowExecutionConfig


@dataclass(frozen=True)
class EventSource:
    trustpoint: bool = True
    ca_id: int | None = None
    domain_id: int | None = None
    device_id: str | None = None


class WorkflowDispatchService:
    """
    Trigger integration:
      - select matching definitions
      - create Workflow2Run + Workflow2Instance rows
      - inline: run now (checkpointed)
      - queue: enqueue jobs (requires worker)
    """

    def __init__(self, *, executor: WorkflowExecutor | None = None) -> None:
        self.executor = executor or WorkflowExecutor()
        self.runtime = WorkflowRuntimeService(executor=self.executor)

    # ---------- NEW: execution decision helpers ----------

    def _load_exec_cfg(self) -> WorkflowExecutionConfig:
        return WorkflowExecutionConfig.load()

    def _worker_available(self, *, stale_after_seconds: int) -> bool:
        cutoff = timezone.now() - timedelta(seconds=stale_after_seconds)
        return Workflow2WorkerHeartbeat.objects.filter(last_seen__gte=cutoff).exists()

    def _should_enqueue(self) -> bool:
        """
        Decide execution mode for THIS web process call.
        """
        cfg = self._load_exec_cfg()
        mode = str(cfg.mode).lower()

        if mode == "inline":
            return False
        if mode == "queue":
            return True

        # AUTO
        stale = int(getattr(cfg, "worker_stale_after_seconds", 30) or 30)
        return self._worker_available(stale_after_seconds=stale)

    # -----------------------------------------------------

    def emit_event(
        self,
        *,
        on: str,
        event: dict[str, Any],
        source: EventSource,
        initial_vars: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> list[Workflow2Instance]:
        run = self.get_or_create_run(
            on=on,
            event=event,
            source=source,
            idempotency_key=idempotency_key,
        )

        # If the run already existed and has instances, just return them.
        existing = list(Workflow2Instance.objects.filter(run=run).order_by("created_at"))
        if existing:
            return existing

        defs = self._select_definitions(on=on, source=source)

        enqueue = self._should_enqueue()

        out: list[Workflow2Instance] = []
        for d in defs:
            inst = self._create_instance(run=run, definition=d, event=event, initial_vars=initial_vars)

            if enqueue:
                self._enqueue_job(instance=inst, kind=Workflow2Job.KIND_RUN)
            else:
                inst = self.runtime.run_instance(inst)

            out.append(inst)

        self.runtime.recompute_run_status(run)
        return out

    @transaction.atomic
    def get_or_create_run(
        self,
        *,
        on: str,
        event: dict[str, Any],
        source: EventSource,
        idempotency_key: str | None = None,
    ) -> Workflow2Run:
        """
        Manual trigger entrypoint for code paths (views/services), not just signals.

        If idempotency_key is provided, reuse an existing non-finalized run with that key.
        """
        if idempotency_key:
            existing = (
                Workflow2Run.objects.select_for_update()
                .filter(trigger_on=on, idempotency_key=idempotency_key, finalized=False)
                .order_by("-created_at")
                .first()
            )
            if existing is not None:
                return existing

        return Workflow2Run.objects.create(
            trigger_on=on,
            event_json=event,
            source_json=asdict(source),
            idempotency_key=idempotency_key,
            status=Workflow2Run.STATUS_QUEUED,
            finalized=False,
        )

    def _select_definitions(self, *, on: str, source: EventSource) -> list[Workflow2Definition]:
        qs = Workflow2Definition.objects.filter(enabled=True, trigger_on=on).order_by("created_at")
        defs = list(qs)

        matched: list[Workflow2Definition] = []
        for d in defs:
            trig = d.ir_json.get("trigger", {}) if isinstance(d.ir_json, dict) else {}
            sources = trig.get("sources", {}) if isinstance(trig, dict) else {}
            if self._matches_sources(sources, source):
                matched.append(d)
        return matched

    @staticmethod
    def _matches_sources(ir_sources: dict[str, Any], source: EventSource) -> bool:
        trustpoint_wide = bool(ir_sources.get("trustpoint", False))
        if trustpoint_wide:
            return True

        ca_ids = ir_sources.get("ca_ids") or []
        domain_ids = ir_sources.get("domain_ids") or []
        device_ids = ir_sources.get("device_ids") or []

        if source.ca_id is not None and source.ca_id in ca_ids:
            return True
        if source.domain_id is not None and source.domain_id in domain_ids:
            return True
        if source.device_id is not None and source.device_id in device_ids:
            return True

        return False

    @transaction.atomic
    def _create_instance(
        self,
        *,
        run: Workflow2Run,
        definition: Workflow2Definition,
        event: dict[str, Any],
        initial_vars: dict[str, Any] | None,
    ) -> Workflow2Instance:
        return self.runtime.create_instance(
            run=run,
            definition=definition,
            event=event,
            initial_vars=initial_vars,
        )

    @transaction.atomic
    def _enqueue_job(self, *, instance: Workflow2Instance, kind: str) -> Workflow2Job:
        if instance.status != Workflow2Instance.STATUS_QUEUED:
            instance.status = Workflow2Instance.STATUS_QUEUED
            instance.save(update_fields=["status", "updated_at"])

        return Workflow2Job.objects.create(instance=instance, kind=kind, status=Workflow2Job.STATUS_QUEUED)
