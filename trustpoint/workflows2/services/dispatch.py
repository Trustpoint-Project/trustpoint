# workflows2/services/dispatch.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import transaction

from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job
from workflows2.services.runtime import WorkflowRuntimeService


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
      - create instance
      - sync: run now (step-by-step checkpointed)
      - db: enqueue a job
    """

    def __init__(self, *, executor: WorkflowExecutor | None = None) -> None:
        self.executor = executor or WorkflowExecutor()
        self.runtime = WorkflowRuntimeService(executor=self.executor)

    def emit_event(
        self,
        *,
        on: str,
        event: dict[str, Any],
        source: EventSource,
        initial_vars: dict[str, Any] | None = None,
    ) -> list[Workflow2Instance]:
        defs = self._select_definitions(on=on, source=source)

        out: list[Workflow2Instance] = []
        for d in defs:
            inst = self._create_instance(definition=d, event=event, initial_vars=initial_vars)

            run_mode = getattr(settings, "WORKFLOWS2_RUN_MODE", "sync")
            if run_mode == "db":
                self._enqueue_job(instance=inst, kind=Workflow2Job.KIND_RUN)
            else:
                inst = self.runtime.run_instance(inst)

            out.append(inst)
        return out

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
        definition: Workflow2Definition,
        event: dict[str, Any],
        initial_vars: dict[str, Any] | None,
    ) -> Workflow2Instance:
        return self.runtime.create_instance(
            definition=definition,
            event=event,
            initial_vars=initial_vars,
        )

    @transaction.atomic
    def _enqueue_job(self, *, instance: Workflow2Instance, kind: str) -> Workflow2Job:
        # Instance stays queued until worker picks it up.
        if instance.status != Workflow2Instance.STATUS_QUEUED:
            instance.status = Workflow2Instance.STATUS_QUEUED
            instance.save(update_fields=["status", "updated_at"])

        return Workflow2Job.objects.create(instance=instance, kind=kind, status=Workflow2Job.STATUS_QUEUED)
