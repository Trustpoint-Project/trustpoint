# workflows2/services/worker.py
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from django.db import transaction
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
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if batch_limit <= 0:
            raise ValueError("batch_limit must be positive")

        self.runtime = runtime
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.batch_limit = batch_limit

    def _start_heartbeat_thread(self, job_id: str, stop: threading.Event) -> threading.Thread:
        # renew at half the lease; never less than 1s
        interval = max(1.0, self.lease_seconds / 2)

        def _loop() -> None:
            while not stop.is_set():
                try:
                    self.heartbeat(job_id)
                except Exception:
                    # don't crash worker because heartbeat failed once
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
        """
        Detect crashed workers: jobs stuck in RUNNING with an expired lease.

        Policy (recommended):
        - Treat as infra failure and RETRY (until max_attempts)
        - If attempts exhausted -> FAIL instance + run
        """
        now = timezone.now()

        stale_jobs = (
            Workflow2Job.objects.select_for_update(skip_locked=True)
            .select_related("instance")  # OK: instance FK is non-null -> INNER JOIN
            .filter(status=Workflow2Job.STATUS_RUNNING)
            .filter(locked_until__isnull=False, locked_until__lte=now)
            .order_by("locked_until", "created_at")
        )

        count = 0
        for job in stale_jobs:
            inst = job.instance
            err = "Lease expired (worker likely crashed)."

            # clear lease first
            job.locked_until = None
            job.locked_by = None

            # Retry if possible
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

                # Put instance back to queued (so run recompute shows queued/running correctly)
                if inst.status not in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_FAILED,
                    Workflow2Instance.STATUS_STOPPED,
                    Workflow2Instance.STATUS_CANCELLED,
                    Workflow2Instance.STATUS_AWAITING,
                }:
                    inst.status = Workflow2Instance.STATUS_QUEUED
                    inst.save(update_fields=["status", "updated_at"])

                # recompute run
                if inst.run_id:
                    run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
                    self.runtime.recompute_run_status(run)

                count += 1
                continue

            # Attempts exhausted -> terminal fail
            job.status = Workflow2Job.STATUS_FAILED
            job.last_error = err
            job.save(update_fields=["status", "last_error", "locked_until", "locked_by", "updated_at"])

            if inst.status not in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_REJECTED,
                Workflow2Instance.STATUS_FAILED,
                Workflow2Instance.STATUS_STOPPED,
                Workflow2Instance.STATUS_CANCELLED,
            }:
                inst.status = Workflow2Instance.STATUS_FAILED
                inst.current_step = None
                inst.save(update_fields=["status", "current_step", "updated_at"])

            if inst.run_id:
                run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
                run.status = Workflow2Run.STATUS_FAILED
                run.finalized = True
                run.save(update_fields=["status", "finalized", "updated_at"])

            count += 1

        return count


    @transaction.atomic
    def resume_instance(self, *, instance: Workflow2Instance) -> Workflow2Job:
        instance = Workflow2Instance.objects.select_for_update().get(id=instance.id)

        if instance.status != Workflow2Instance.STATUS_PAUSED:
            raise ValueError("Can only resume instances in PAUSED state")

        instance.status = Workflow2Instance.STATUS_QUEUED
        instance.save(update_fields=["status", "updated_at"])

        return Workflow2Job.objects.create(
            instance=instance,
            kind=Workflow2Job.KIND_RESUME,
            status=Workflow2Job.STATUS_QUEUED,
            run_after=timezone.now(),
        )

    @transaction.atomic
    def _claim_one(self) -> Optional[Workflow2Job]:
        now = timezone.now()
        lease_until = now + timedelta(seconds=self.lease_seconds)

        qs = (
            Workflow2Job.objects.select_for_update(skip_locked=True)
            .filter(status=Workflow2Job.STATUS_QUEUED, run_after__lte=now)
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

                if inst.status == Workflow2Instance.STATUS_PAUSED:
                    skipped = True
                    self._mark_done(job)
                    return True, False, skipped

                if inst.status in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_FAILED,
                    Workflow2Instance.STATUS_STOPPED,
                    Workflow2Instance.STATUS_CANCELLED,
                }:
                    skipped = True
                    self._mark_done(job)
                    return True, False, skipped

                # Mark instance/run as running (helps UI stay consistent)
                if inst.status != Workflow2Instance.STATUS_RUNNING:
                    inst.status = Workflow2Instance.STATUS_RUNNING
                    inst.save(update_fields=["status", "updated_at"])

                if inst.run_id:
                    Workflow2Run.objects.filter(id=inst.run_id).update(
                        status=Workflow2Run.STATUS_RUNNING,
                        updated_at=timezone.now(),
                    )

                step_res = self.runtime.run_one_step(inst)

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
                    # Terminal outcome: ensure run is finalized (runtime may already do this;
                    # this is a safety net for UI consistency).
                    if inst.run_id:
                        # instance status should already have been set by runtime;
                        # but run can be finalized here if not.
                        Workflow2Run.objects.filter(id=inst.run_id).update(
                            finalized=True,
                            updated_at=timezone.now(),
                        )

            return True, created_next, skipped

        except Exception as e:  # noqa: BLE001
            self._handle_failure(job, e)
            return False, False, False

        finally:
            stop_evt.set()
            # best effort join; don't hang shutdown
            hb_thread.join(timeout=1.0)

    @transaction.atomic
    def _mark_done(self, job: Workflow2Job) -> None:
        job.status = Workflow2Job.STATUS_DONE
        job.locked_until = None
        job.locked_by = None
        job.last_error = None
        job.save(update_fields=["status", "locked_until", "locked_by", "last_error", "updated_at"])

    @transaction.atomic
    def _handle_failure(self, job: Workflow2Job, exc: Exception) -> None:
        """
        Failure policy:
        - Retry with exponential backoff until max_attempts is reached
        - On terminal failure: mark job FAILED and also mark instance/run FAILED
        """
        job = Workflow2Job.objects.select_for_update().select_related("instance").get(id=job.id)
        inst = job.instance
        err = f"{type(exc).__name__}: {exc}"

        # IMPORTANT: schedule_retry() increments attempts
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

            # put instance back to queued (so UI doesn't show RUNNING forever)
            if inst.status not in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_REJECTED,
                Workflow2Instance.STATUS_FAILED,
                Workflow2Instance.STATUS_STOPPED,
                Workflow2Instance.STATUS_CANCELLED,
                Workflow2Instance.STATUS_AWAITING,
            }:
                inst.status = Workflow2Instance.STATUS_QUEUED
                inst.save(update_fields=["status", "updated_at"])

            if inst.run_id:
                run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
                self.runtime.recompute_run_status(run)

            return

        # Terminal failure
        job.status = Workflow2Job.STATUS_FAILED
        job.last_error = err
        job.locked_until = None
        job.locked_by = None
        job.save(update_fields=["status", "last_error", "locked_until", "locked_by", "updated_at"])

        if inst.status not in {
            Workflow2Instance.STATUS_SUCCEEDED,
            Workflow2Instance.STATUS_REJECTED,
            Workflow2Instance.STATUS_FAILED,
            Workflow2Instance.STATUS_STOPPED,
            Workflow2Instance.STATUS_CANCELLED,
        }:
            inst.status = Workflow2Instance.STATUS_FAILED
            inst.current_step = None
            inst.save(update_fields=["status", "current_step", "updated_at"])

        if inst.run_id:
            run = Workflow2Run.objects.select_for_update().get(id=inst.run_id)
            run.status = Workflow2Run.STATUS_FAILED
            run.finalized = True
            run.save(update_fields=["status", "finalized", "updated_at"])
