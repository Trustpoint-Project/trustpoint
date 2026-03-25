"""Dispatch workflow runs from incoming events using inline or queued execution."""
from __future__ import annotations

import time
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import timedelta
from functools import partial
from typing import Any, Literal

from django.conf import settings
from django.db import OperationalError, connection, transaction
from django.utils import timezone

from management.models.workflows2 import WorkflowExecutionConfig
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import (
    Workflow2Definition,
    Workflow2Instance,
    Workflow2Job,
    Workflow2Run,
    Workflow2WorkerHeartbeat,
)
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker

DispatchStatus = Literal['no_match', 'completed', 'blocked', 'running']


@dataclass(frozen=True)
class DispatchOutcome:
    """Describe the high-level outcome of dispatching one event."""

    status: DispatchStatus
    run: Workflow2Run
    instances: list[Workflow2Instance]


@dataclass(frozen=True)
class EventSource:
    """Describe the source scope attached to one emitted event."""

    trustpoint: bool = True
    ca_id: int | None = None
    domain_id: int | None = None
    device_id: str | None = None


class WorkflowDispatchService:
    """Provide event dispatch with one scheduling model.

    Single scheduling system:
      - ALWAYS create Workflow2Job rows.
      - Execution ALWAYS happens via worker semantics (one step per job).
      - "sync/inline" means: enqueue jobs and drain them in-process until blocked/finished.
      - "db/queue" means: enqueue jobs and return (external worker continues).

    SQLite note:
      - If dispatch runs inside a transaction (common during model save),
        draining immediately can trigger 'database is locked'.
      - We therefore drain via transaction.on_commit when inside an atomic block.
    """

    def __init__(self, *, executor: WorkflowExecutor | None = None) -> None:
        """Initialize the dispatch service and its runtime dependency."""
        self.executor = executor or WorkflowExecutor()
        self.runtime = WorkflowRuntimeService(executor=self.executor)

    def _load_exec_cfg(self) -> WorkflowExecutionConfig:
        return WorkflowExecutionConfig.load()

    def _worker_available(self, *, stale_after_seconds: int) -> bool:
        cutoff = timezone.now() - timedelta(seconds=stale_after_seconds)
        return Workflow2WorkerHeartbeat.objects.filter(last_seen__gte=cutoff).exists()

    def _effective_mode(self) -> str:
        """Returns "sync" or "db".

        Priority:
          1) Django setting WORKFLOWS2_RUN_MODE:
             - "sync" => drain in-process
             - "db"   => enqueue only
          2) WorkflowExecutionConfig.mode:
             - "inline" => sync
             - "queue"  => db
             - "auto"   => db if worker present else sync
        """
        run_mode = getattr(settings, 'WORKFLOWS2_RUN_MODE', None)
        if run_mode:
            m = str(run_mode).lower()
            if m in {'sync', 'inline'}:
                return 'sync'
            if m in {'db', 'queue'}:
                return 'db'

        cfg = self._load_exec_cfg()
        mode = str(cfg.mode).lower()

        if mode == 'inline':
            return 'sync'
        if mode == 'queue':
            return 'db'

        stale = int(getattr(cfg, 'worker_stale_after_seconds', 30) or 30)
        return 'db' if self._worker_available(stale_after_seconds=stale) else 'sync'

    def runs_inline(self) -> bool:
        """Return whether dispatch currently drains jobs inline."""
        return self._effective_mode() == 'sync'

    def _drain_jobs_in_process(self, *, worker_id: str = 'inline-worker', max_ticks: int = 200) -> None:
        """Drain runnable jobs until nothing is claimable (blocked or empty).

        For inline drain we disable heartbeat to avoid concurrent DB writes.
        Also includes a small SQLite lock backoff.
        """
        worker = Workflow2DbWorker(
            runtime=self.runtime,
            worker_id=worker_id,
            lease_seconds=5,
            batch_limit=50,
            heartbeat_enabled=False,
        )

        for i in range(max_ticks):
            try:
                stats = worker.tick()
            except OperationalError as e:
                msg = str(e).lower()
                if connection.vendor == 'sqlite' and 'database is locked' in msg:
                    # brief backoff; lock should clear after outer transaction commits
                    time.sleep(min(0.25, 0.01 * (i + 1)))
                    continue
                raise

            if stats.claimed == 0 and stats.recovered == 0:
                return

        msg = 'Inline drain exceeded max_ticks (possible infinite job loop)'
        raise RuntimeError(msg)

    def _drain_after_commit(self, run_id: str | None = None) -> None:
        """Drain queued jobs after commit and refresh the run status."""
        try:
            self._drain_jobs_in_process(worker_id='inline-worker')
        finally:
            with suppress(Exception):
                if run_id:
                    run = Workflow2Run.objects.get(id=run_id)
                    self.runtime.recompute_run_status(run)

    def emit_event(
        self,
        *,
        on: str,
        event: dict[str, Any],
        source: EventSource,
        initial_vars: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> list[Workflow2Instance]:
        """Dispatch an event and return any created workflow instances."""
        run = self.get_or_create_run(
            on=on,
            event=event,
            source=source,
            idempotency_key=idempotency_key,
        )

        existing = list(Workflow2Instance.objects.filter(run=run).order_by('created_at'))
        if existing:
            self.runtime.recompute_run_status(run)
            return existing

        defs = self._select_definitions(on=on, source=source)
        if not defs:
            run.status = Workflow2Run.STATUS_NO_MATCH
            run.finalized = True
            run.save(update_fields=['status', 'finalized', 'updated_at'])
            return []

        mode = self._effective_mode()

        out: list[Workflow2Instance] = []
        for d in defs:
            inst = self._create_instance(run=run, definition=d, event=event, initial_vars=initial_vars)
            self._enqueue_job(instance=inst, kind=Workflow2Job.KIND_RUN)
            out.append(inst)

        if mode == 'sync':
            # If we are inside an atomic block (e.g. device creation), draining now can lock SQLite.
            # Drain right after commit instead.
            if connection.in_atomic_block:
                transaction.on_commit(partial(self._drain_after_commit, str(run.id)))
            else:
                self._drain_jobs_in_process(worker_id='inline-worker')
                self.runtime.recompute_run_status(run)
        else:
            self.runtime.recompute_run_status(run)

        return out

    def emit_event_outcome(
        self,
        *,
        on: str,
        event: dict[str, Any],
        source: EventSource,
        initial_vars: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> DispatchOutcome:
        """Dispatch an event and return a high-level status summary."""
        instances = self.emit_event(
            on=on,
            event=event,
            source=source,
            initial_vars=initial_vars,
            idempotency_key=idempotency_key,
        )

        run = (
            Workflow2Run.objects.filter(trigger_on=on, idempotency_key=idempotency_key)
            .order_by('-created_at')
            .first()
        )
        if run is None:
            msg = 'emit_event created instances but no run was found'
            raise RuntimeError(msg)

        if len(instances) == 0:
            self.runtime.recompute_run_status(run)
            run.refresh_from_db(fields=['status', 'finalized', 'updated_at'])
            return DispatchOutcome(status='no_match', run=run, instances=[])

        run.refresh_from_db(fields=['status', 'finalized', 'updated_at'])

        if run.status in {Workflow2Run.STATUS_AWAITING, Workflow2Run.STATUS_PAUSED}:
            return DispatchOutcome(status='blocked', run=run, instances=instances)

        if run.status in {
            Workflow2Run.STATUS_SUCCEEDED,
            Workflow2Run.STATUS_REJECTED,
            Workflow2Run.STATUS_FAILED,
            Workflow2Run.STATUS_CANCELLED,
        }:
            return DispatchOutcome(status='completed', run=run, instances=instances)

        return DispatchOutcome(status='running', run=run, instances=instances)

    def continue_instance(self, *, instance: Workflow2Instance) -> Workflow2Job:
        """Queue the next job for an existing instance and apply normal dispatch policy."""
        job = Workflow2Job.objects.create(
            instance=instance,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
        )

        run_id = getattr(instance, 'run_id', None)
        if run_id:
            run = Workflow2Run.objects.get(id=run_id)
            self.runtime.recompute_run_status(run)

        if self.runs_inline():
            if connection.in_atomic_block:
                transaction.on_commit(partial(self._drain_after_commit, str(run_id) if run_id else None))
            else:
                self._drain_jobs_in_process(worker_id='inline-worker')
                if run_id:
                    run = Workflow2Run.objects.get(id=run_id)
                    self.runtime.recompute_run_status(run)

        return job

    @transaction.atomic
    def get_or_create_run(
        self,
        *,
        on: str,
        event: dict[str, Any],
        source: EventSource,
        idempotency_key: str | None = None,
    ) -> Workflow2Run:
        """Return an existing idempotent run or create a new one."""
        if idempotency_key:
            existing = (
                Workflow2Run.objects.select_for_update()
                .filter(trigger_on=on, idempotency_key=idempotency_key)
                .order_by('-created_at')
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
        """Return enabled definitions matching the trigger and source scope."""
        qs = Workflow2Definition.objects.filter(enabled=True, trigger_on=on).order_by('created_at')
        defs = list(qs)

        matched: list[Workflow2Definition] = []
        for d in defs:
            trig = d.ir_json.get('trigger', {}) if isinstance(d.ir_json, dict) else {}
            sources = trig.get('sources', {}) if isinstance(trig, dict) else {}
            if self._matches_sources(sources, source):
                matched.append(d)
        return matched

    @staticmethod
    def _matches_sources(ir_sources: dict[str, Any], source: EventSource) -> bool:
        """Return whether one definition source filter matches the event source."""
        trustpoint_wide = bool(ir_sources.get('trustpoint', False))
        if trustpoint_wide:
            return True

        ca_ids = ir_sources.get('ca_ids') or []
        domain_ids = ir_sources.get('domain_ids') or []
        device_ids = ir_sources.get('device_ids') or []

        if source.ca_id is not None and source.ca_id in ca_ids:
            return True
        if source.domain_id is not None and source.domain_id in domain_ids:
            return True
        return source.device_id is not None and source.device_id in device_ids

    @transaction.atomic
    def _create_instance(
        self,
        *,
        run: Workflow2Run,
        definition: Workflow2Definition,
        event: dict[str, Any],
        initial_vars: dict[str, Any] | None,
    ) -> Workflow2Instance:
        """Create one workflow instance for a matched definition."""
        return self.runtime.create_instance(
            run=run,
            definition=definition,
            event=event,
            initial_vars=initial_vars,
        )

    @transaction.atomic
    def _enqueue_job(self, *, instance: Workflow2Instance, kind: str) -> Workflow2Job:
        """Create a queued job for a workflow instance."""
        if instance.status != Workflow2Instance.STATUS_QUEUED:
            instance.status = Workflow2Instance.STATUS_QUEUED
            instance.save(update_fields=['status', 'updated_at'])

        return Workflow2Job.objects.create(instance=instance, kind=kind, status=Workflow2Job.STATUS_QUEUED)
