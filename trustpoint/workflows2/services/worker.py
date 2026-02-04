# workflows2/services/worker.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from workflows2.models import Workflow2Instance, Workflow2Job
from workflows2.services.runtime import WorkflowRuntimeService


@dataclass(frozen=True)
class WorkerStats:
    claimed: int
    processed: int
    created_next_jobs: int
    skipped: int
    recovered: int  # number of stale RUNNING jobs recovered (lease expired)


class Workflow2DbWorker:
    """
    DB-backed worker (no external infra).

    Design:
      - Exactly one step per job => crash-resumable.
      - Lease to avoid duplicate processing if worker crashes.
      - If we detect a RUNNING job whose lease expired, we PAUSE the instance
        and require manual resume.
    """

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

    def tick(self) -> WorkerStats:
        # 1) Crash recovery sweep
        recovered = self._recover_stale_running_jobs()

        claimed = 0
        processed = 0
        created_next = 0
        skipped = 0

        # 2) Normal processing loop
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
    def _recover_stale_running_jobs(self) -> int:
        """
        Detect crashed workers: jobs stuck in RUNNING with an expired lease.

        Policy:
          - Mark job FAILED with lease-expired error
          - Mark instance PAUSED (non-terminal, requires manual resume)
        """
        now = timezone.now()

        stale_jobs = (
            Workflow2Job.objects.select_for_update(skip_locked=True)
            .select_related("instance")
            .filter(status=Workflow2Job.STATUS_RUNNING)
            .filter(locked_until__isnull=False, locked_until__lte=now)
            .order_by("locked_until", "created_at")
        )

        count = 0
        for job in stale_jobs:
            inst = job.instance

            # Mark job failed
            job.status = Workflow2Job.STATUS_FAILED
            job.last_error = "Lease expired (worker likely crashed). Instance paused; manual resume required."
            job.locked_until = None
            job.locked_by = None
            job.save(update_fields=["status", "last_error", "locked_until", "locked_by", "updated_at"])

            # Pause instance if it isn't already terminal
            if inst.status not in {
                Workflow2Instance.STATUS_SUCCEEDED,
                Workflow2Instance.STATUS_FAILED,
                Workflow2Instance.STATUS_STOPPED,
                Workflow2Instance.STATUS_CANCELLED,
            }:
                inst.status = Workflow2Instance.STATUS_PAUSED
                inst.save(update_fields=["status", "updated_at"])

            count += 1

        return count

    @transaction.atomic
    def resume_instance(self, *, instance: Workflow2Instance) -> Workflow2Job:
        """
        Manual operator action:
          - instance must be PAUSED (or AWAITING, depending on your future signal model)
          - enqueue a job to continue from instance.current_step
        """
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
        """
        Returns: (ok, created_next_job, skipped)
        """
        created_next = False
        skipped = False

        try:
            with transaction.atomic():
                inst = Workflow2Instance.objects.select_for_update().get(id=job.instance_id)

                # Do not auto-run paused instances. Must be resumed explicitly.
                if inst.status == Workflow2Instance.STATUS_PAUSED:
                    skipped = True
                    self._mark_done(job)
                    return True, False, skipped

                # Already terminal? finalize job and count as skipped.
                if inst.status in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_FAILED,
                    Workflow2Instance.STATUS_STOPPED,
                    Workflow2Instance.STATUS_CANCELLED,
                }:
                    skipped = True
                    self._mark_done(job)
                    return True, False, skipped

                # Execute exactly one step and checkpoint.
                step_res = self.runtime.run_one_step(inst)

                # Mark job done
                self._mark_done(job)

                # If still not terminal, enqueue next job immediately
                if not step_res.terminal:
                    Workflow2Job.objects.create(
                        instance=inst,
                        kind=Workflow2Job.KIND_RUN,
                        status=Workflow2Job.STATUS_QUEUED,
                        run_after=timezone.now(),
                    )
                    created_next = True

            return True, created_next, skipped

        except Exception as e:  # noqa: BLE001
            self._handle_failure(job, e)
            return False, False, False

    @transaction.atomic
    def _mark_done(self, job: Workflow2Job) -> None:
        job.status = Workflow2Job.STATUS_DONE
        job.locked_until = None
        job.locked_by = None
        job.last_error = None
        job.save(update_fields=["status", "locked_until", "locked_by", "last_error", "updated_at"])

    @transaction.atomic
    def _handle_failure(self, job: Workflow2Job, exc: Exception) -> None:
        job = Workflow2Job.objects.select_for_update().get(id=job.id)
        err = f"{type(exc).__name__}: {exc}"

        # retry if possible
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
            return

        # no retries left => mark failed
        job.status = Workflow2Job.STATUS_FAILED
        job.last_error = err
        job.locked_until = None
        job.locked_by = None
        job.save(update_fields=["status", "last_error", "locked_until", "locked_by", "updated_at"])
