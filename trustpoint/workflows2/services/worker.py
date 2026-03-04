# workflows2/services/worker.py
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone

from workflows2.models import Workflow2Instance, Workflow2Job, Workflow2Run
from workflows2.services.runtime import WorkflowRuntimeService


@dataclass(frozen=True)
class WorkerStats:
    claimed: int
    processed: int
    created_next_jobs: int
    skipped: int
    recovered: int


class Workflow2DbWorker:
    def __init__(
        self,
        *,
        runtime: WorkflowRuntimeService,
        worker_id: str,
        lease_seconds: int = 30,
        batch_limit: int = 1,
        heartbeat_enabled: bool = True,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if batch_limit <= 0:
            raise ValueError("batch_limit must be positive")

        self.runtime = runtime
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.batch_limit = batch_limit

        # Heartbeat is useful for long-running external worker steps.
        # On SQLite (dev), it causes extra concurrent writes and frequently triggers
        # "database is locked". For inline drain we also disable it explicitly.
        self.heartbeat_enabled = bool(heartbeat_enabled) and (connection.vendor != "sqlite")

    def _start_heartbeat_thread(self, job_id: str, stop: threading.Event) -> threading.Thread:
        if not self.heartbeat_enabled:
            t = threading.Thread(target=lambda: None, daemon=True)
            t.start()
            return t

        # renew at half the lease; never less than 1s
        interval = max(1.0, self.lease_seconds / 2)

        def _loop() -> None:
            while not stop.is_set():
                try:
                    self.heartbeat(job_id)
                except Exception:
                    # best-effort only
                    pass
                stop.wait(interval)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        return t

    def tick(self) -> WorkerStats:
        recovered = self._recover_stale_running_jobs()

        claimed = 0
        processed = 0
        created_next = 0
        skipped = 0

        for _ in range(self.batch_limit):
            job = self._claim_one()
            if job is None:
                break
            claimed += 1

            ok, made_next, did_skip = self._process_job(job)
            processed += 1
            created_next += (1 if made_next else 0)
            skipped += (1 if did_skip else 0)

        return WorkerStats(
            claimed=claimed,
            processed=processed,
            created_next_jobs=created_next,
            skipped=skipped,
            recovered=recovered,
        )

    @transaction.atomic
    def heartbeat(self, job_id: str) -> bool:
        now = timezone.now()
        lease_until = now + timedelta(seconds=self.lease_seconds)
        updated = Workflow2Job.objects.filter(
            id=job_id,
            status=Workflow2Job.STATUS_RUNNING,
            locked_by=self.worker_id,
        ).update(locked_until=lease_until, updated_at=now)
        return updated == 1

    @transaction.atomic
    def _recover_stale_running_jobs(self) -> int:
        now = timezone.now()

        qs = Workflow2Job.objects.select_for_update(skip_locked=True)
        if connection.vendor == "sqlite":
            # sqlite doesn't support real row locking; still works as best-effort
            qs = Workflow2Job.objects.select_for_update()

        stale_jobs = (
            qs.select_related("instance")
            .filter(status=Workflow2Job.STATUS_RUNNING)
            .filter(locked_until__isnull=False, locked_until__lte=now)
            .order_by("locked_until", "created_at")
        )

        count = 0
        for job in stale_jobs:
            inst = job.instance
            err = "Lease expired (worker likely crashed)."

            job.status = Workflow2Job.STATUS_FAILED
            job.last_error = err
            job.locked_until = None
            job.locked_by = None
            job.save(update_fields=["status", "last_error", "locked_until", "locked_by", "updated_at"])

            if inst.status not in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_REJECTED,
                Workflow2Instance.STATUS_CANCELLED,
                Workflow2Instance.STATUS_AWAITING,
            }:
                inst.status = Workflow2Instance.STATUS_PAUSED
                inst.save(update_fields=["status", "updated_at"])

            if inst.run_id:
                run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
                self.runtime.recompute_run_status(run)

            count += 1

        return count

    @transaction.atomic
    def retry_instance(self, *, instance: Workflow2Instance) -> Workflow2Job:
        instance = Workflow2Instance.objects.select_for_update().get(id=instance.id)

        if instance.status not in {Workflow2Instance.STATUS_FAILED, Workflow2Instance.STATUS_PAUSED}:
            raise ValueError("Can only retry instances in FAILED/PAUSED state")

        instance.status = Workflow2Instance.STATUS_QUEUED
        instance.save(update_fields=["status", "updated_at"])

        return Workflow2Job.objects.create(
            instance=instance,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
            run_after=timezone.now(),
        )

    def resume_instance(self, *, instance: Workflow2Instance) -> Workflow2Job:
        return self.retry_instance(instance=instance)

    @transaction.atomic
    def _claim_one(self) -> Optional[Workflow2Job]:
        now = timezone.now()
        lease_until = now + timedelta(seconds=self.lease_seconds)

        qs = Workflow2Job.objects.select_for_update(skip_locked=True)
        if connection.vendor == "sqlite":
            qs = Workflow2Job.objects.select_for_update()

        qs = (
            qs.filter(status=Workflow2Job.STATUS_QUEUED, run_after__lte=now)
            .filter(Q(locked_until__isnull=True) | Q(locked_until__lte=now))
            .order_by("run_after", "created_at")
        )

        job = qs.first()
        if job is None:
            return None

        job.status = Workflow2Job.STATUS_RUNNING
        job.locked_until = lease_until
        job.locked_by = self.worker_id
        job.save(update_fields=["status", "locked_until", "locked_by", "updated_at"])
        return job

    def _process_job(self, job: Workflow2Job) -> tuple[bool, bool, bool]:
        created_next = False
        skipped = False

        stop_evt = threading.Event()
        hb_thread = self._start_heartbeat_thread(str(job.id), stop_evt)

        try:
            with transaction.atomic():
                inst = Workflow2Instance.objects.select_for_update().get(id=job.instance_id)

                if inst.status in {Workflow2Instance.STATUS_PAUSED, Workflow2Instance.STATUS_AWAITING}:
                    skipped = True
                    self._mark_done(job)
                    return True, False, skipped

                if inst.status in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_CANCELLED,
                }:
                    skipped = True
                    self._mark_done(job)
                    return True, False, skipped

                if inst.status != Workflow2Instance.STATUS_RUNNING:
                    inst.status = Workflow2Instance.STATUS_RUNNING
                    inst.save(update_fields=["status", "updated_at"])

                if inst.run_id:
                    Workflow2Run.objects.filter(id=inst.run_id).update(
                        status=Workflow2Run.STATUS_RUNNING,
                        updated_at=timezone.now(),
                    )

            # Important: execute step OUTSIDE the outer atomic to reduce SQLite lock duration.
            # run_one_step() has its own transaction handling and failure persistence.
            step_res = self.runtime.run_one_step(inst)

            with transaction.atomic():
                self._mark_done(job)

                if not step_res.terminal:
                    Workflow2Job.objects.create(
                        instance=inst,
                        kind=Workflow2Job.KIND_RUN,
                        status=Workflow2Job.STATUS_QUEUED,
                        run_after=timezone.now(),
                    )
                    created_next = True
                else:
                    if inst.run_id:
                        run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
                        self.runtime.recompute_run_status(run)

            return True, created_next, skipped

        except Exception as e:  # noqa: BLE001
            self._handle_failure(job, e)
            return False, False, False

        finally:
            stop_evt.set()
            hb_thread.join(timeout=1.0)

    @transaction.atomic
    def _mark_done(self, job: Workflow2Job) -> None:
        job = Workflow2Job.objects.select_for_update().get(id=job.id)
        job.status = Workflow2Job.STATUS_DONE
        job.locked_until = None
        job.locked_by = None
        job.last_error = None
        job.save(update_fields=["status", "locked_until", "locked_by", "last_error", "updated_at"])

    @transaction.atomic
    def _handle_failure(self, job: Workflow2Job, exc: Exception) -> None:
        job = Workflow2Job.objects.select_for_update().select_related("instance").get(id=job.id)
        inst = job.instance
        err = f"{type(exc).__name__}: {exc}"

        if job.attempts < job.max_attempts:
            job.schedule_retry(error=err)
            job.save(
                update_fields=[
                    "attempts",
                    "last_error",
                    "run_after",
                    "status",
                    "locked_until",
                    "locked_by",
                    "updated_at",
                ]
            )

            if inst.status not in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_REJECTED,
                Workflow2Instance.STATUS_CANCELLED,
                Workflow2Instance.STATUS_AWAITING,
            }:
                inst.status = Workflow2Instance.STATUS_QUEUED
                inst.save(update_fields=["status", "updated_at"])

            if inst.run_id:
                run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
                self.runtime.recompute_run_status(run)
            return

        # Attempts exhausted => pause for human retry (do NOT finalize)
        job.status = Workflow2Job.STATUS_FAILED
        job.last_error = err
        job.locked_until = None
        job.locked_by = None
        job.save(update_fields=["status", "last_error", "locked_until", "locked_by", "updated_at"])

        if inst.status not in {
            Workflow2Instance.STATUS_SUCCEEDED,
            Workflow2Instance.STATUS_REJECTED,
            Workflow2Instance.STATUS_CANCELLED,
            Workflow2Instance.STATUS_AWAITING,
        }:
            inst.status = Workflow2Instance.STATUS_FAILED
            inst.save(update_fields=["status", "updated_at"])

        if inst.run_id:
            run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
            self.runtime.recompute_run_status(run)