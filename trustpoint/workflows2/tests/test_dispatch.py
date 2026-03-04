from __future__ import annotations

from django.test import TestCase

from management.models import WorkflowExecutionConfig
from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job
from workflows2.services.dispatch import EventSource, WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


YAML_TRUSTPOINT = """
schema: trustpoint.workflow.v2
name: TP device created
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


class DispatchTests(TestCase):
    def _store_definition(self) -> Workflow2Definition:
        ir = compile_workflow_yaml(YAML_TRUSTPOINT)
        return Workflow2Definition.objects.create(
            name="TP device created",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=YAML_TRUSTPOINT,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

    def test_dispatch_creates_instance_for_matching_trigger_sync(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.INLINE
        cfg.save()

        self._store_definition()

        svc = WorkflowDispatchService()
        instances = svc.emit_event(
            on="device.created",
            event={"device": {"common_name": "dev1"}},
            source=EventSource(trustpoint=True),
        )

        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0].definition.name, "TP device created")
        instances[0].refresh_from_db()
        self.assertEqual(instances[0].status, Workflow2Instance.STATUS_SUCCEEDED)

        # Single scheduling mechanism: jobs exist even in inline mode (they are just drained).
        self.assertGreaterEqual(Workflow2Job.objects.filter(instance=instances[0]).count(), 1)

    def test_dispatch_creates_instance_for_matching_trigger_db(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.QUEUE
        cfg.save()

        self._store_definition()

        svc = WorkflowDispatchService()
        instances = svc.emit_event(
            on="device.created",
            event={"device": {"common_name": "dev1"}},
            source=EventSource(trustpoint=True),
        )

        self.assertEqual(len(instances), 1)
        inst = instances[0]
        inst.refresh_from_db()

        # In QUEUE mode, dispatch enqueues; instance is not executed yet.
        self.assertEqual(inst.status, Workflow2Instance.STATUS_QUEUED)
        self.assertEqual(Workflow2Job.objects.filter(instance=inst, status=Workflow2Job.STATUS_QUEUED).count(), 1)

        # Run worker once -> should execute and mark succeeded.
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id="test-worker")
        stats = worker.tick()
        self.assertEqual(stats.claimed, 1)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_SUCCEEDED)

    def test_dispatch_ignores_non_matching_trigger(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.QUEUE
        cfg.save()

        self._store_definition()

        svc = WorkflowDispatchService()
        instances = svc.emit_event(
            on="device.updated",
            event={"device": {"common_name": "dev1"}},
            source=EventSource(trustpoint=True),
        )

        self.assertEqual(instances, [])