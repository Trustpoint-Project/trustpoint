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
name: Worker test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: done_ok
  steps:
    done_ok:
      type: set
      vars: {}
  flow: []
"""


class WorkerTests(TestCase):
    def test_worker_claims_and_runs_job(self) -> None:
        ir = compile_workflow_yaml(YAML_OK)
        d = Workflow2Definition.objects.create(
            name="Worker test",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=YAML_OK,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

        ex = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=ex)
        inst = runtime.create_instance(definition=d, event={"device": {"common_name": "dev1"}})

        job = Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
            run_after=timezone.now() - timedelta(seconds=1),
        )

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id="test-worker")
        stats = worker.tick()

        job.refresh_from_db()
        inst.refresh_from_db()

        self.assertEqual(stats.claimed, 1)
        self.assertEqual(job.status, Workflow2Job.STATUS_DONE)
        self.assertEqual(inst.status, Workflow2Instance.STATUS_SUCCEEDED)

    def test_worker_skips_terminal_instance(self) -> None:
        ir = compile_workflow_yaml(YAML_OK)
        d = Workflow2Definition.objects.create(
            name="Worker test",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=YAML_OK,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

        ex = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=ex)
        inst = runtime.create_instance(definition=d, event={"device": {"common_name": "dev1"}})
        inst.status = Workflow2Instance.STATUS_SUCCEEDED
        inst.save(update_fields=["status", "updated_at"])

        job = Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
            run_after=timezone.now() - timedelta(seconds=1),
        )

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id="test-worker")
        stats = worker.tick()

        job.refresh_from_db()
        self.assertEqual(stats.claimed, 1)
        self.assertEqual(stats.skipped, 1)
        self.assertEqual(job.status, Workflow2Job.STATUS_DONE)
