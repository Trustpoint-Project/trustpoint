from __future__ import annotations

import time
from dataclasses import dataclass

from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


@dataclass
class FakeRun:
    run_index: int
    step_id: str
    step_type: str
    status: str
    outcome: str | None
    next_step: str | None
    vars_delta: dict | None
    output: dict | None
    error: str | None


class SlowExecutor:
    def execute_single_step(self, *, ir, step_id, run_index, ctx, transitions):
        # Simulate a slow external call that would outlive the lease
        time.sleep(2.0)
        # terminal succeed
        return FakeRun(
            run_index=run_index,
            step_id=step_id,
            step_type="stop",
            status="succeeded",
            outcome=None,
            next_step=None,
            vars_delta={},
            output={},
            error=None,
        )


class WorkerHeartbeatTests(TransactionTestCase):
    reset_sequences = True

    @override_settings(WORKFLOWS2_RUN_MODE="db")
    def test_heartbeat_renews_lease_while_step_runs(self) -> None:
        # Minimal IR: one step that "succeeds"
        ir = {
            "workflow": {
                "start": "a",
                "steps": {"a": {"type": "stop", "params": {}}},
                "transitions": {},
            },
            "trigger": {"on": "x"},
        }

        d = Workflow2Definition.objects.create(
            name="hb",
            enabled=True,
            trigger_on="x",
            yaml_text="",
            ir_json=ir,
            ir_hash="x",
        )

        runtime = WorkflowRuntimeService(executor=SlowExecutor(), max_steps_per_run=10)

        inst = runtime.create_instance(definition=d, event={"x": 1}, initial_vars={})
        job = Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
            run_after=timezone.now(),
        )

        worker = Workflow2DbWorker(runtime=runtime, worker_id="t1", lease_seconds=1, batch_limit=1)

        # One tick should claim + process job and succeed despite step taking > lease_seconds
        stats = worker.tick()
        self.assertEqual(stats.claimed, 1)
        self.assertEqual(stats.processed, 1)

        job.refresh_from_db()
        inst.refresh_from_db()

        self.assertEqual(job.status, Workflow2Job.STATUS_DONE)
        self.assertEqual(inst.status, Workflow2Instance.STATUS_SUCCEEDED)
