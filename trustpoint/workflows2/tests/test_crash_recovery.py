from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


YAML_OK = """
schema: trustpoint.workflow.v2
name: Crash recovery test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: done_ok
  steps:
    done_ok:
      type: succeed
      message: Done
  flow: []
"""


class CrashRecoveryTests(TestCase):
    def _mk_definition(self) -> Workflow2Definition:
        ir = compile_workflow_yaml(YAML_OK)
        return Workflow2Definition.objects.create(
            name="Crash recovery test",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=YAML_OK,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

    def test_worker_recovers_stale_running_job_and_cancels_instance(self) -> None:
        d = self._mk_definition()
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        inst = runtime.create_instance(definition=d, event={"device": {"common_name": "dev1"}})

        # Pretend we started execution and crashed mid-flight
        inst.status = Workflow2Instance.STATUS_RUNNING
        inst.save(update_fields=["status", "updated_at"])

        job = Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_RUNNING,
            run_after=timezone.now() - timedelta(seconds=5),
            locked_by="dead-worker",
            locked_until=timezone.now() - timedelta(seconds=1),  # lease expired
        )

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=1, worker_id="test-worker")
        stats = worker.tick()

        job.refresh_from_db()
        inst.refresh_from_db()

        self.assertEqual(stats.recovered, 1)
        self.assertEqual(job.status, Workflow2Job.STATUS_FAILED)
        self.assertEqual(inst.status, Workflow2Instance.STATUS_PAUSED)

    def test_manual_resume_enqueues_job_and_allows_worker_to_finish(self) -> None:
        d = self._mk_definition()
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        inst = runtime.create_instance(definition=d, event={"device": {"common_name": "dev1"}})

        # Simulate "paused after crash"
        inst.status = Workflow2Instance.STATUS_PAUSED
        inst.save(update_fields=["status", "updated_at"])

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id="test-worker")

        # manual resume action
        resume_job = worker.resume_instance(instance=inst)
        self.assertEqual(resume_job.status, Workflow2Job.STATUS_QUEUED)

        stats = worker.tick()
        self.assertGreaterEqual(stats.claimed, 1)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_SUCCEEDED)
