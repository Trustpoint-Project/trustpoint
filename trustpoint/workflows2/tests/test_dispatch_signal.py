from __future__ import annotations

from django.test import TestCase, override_settings

from devices.models import DeviceModel
from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job
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
  start: stop_ok

  steps:
    stop_ok:
      type: stop
      reason: Done

  flow: []
"""


class DispatchSignalsTests(TestCase):
    def _store_definition(self) -> None:
        ir = compile_workflow_yaml(YAML_TRUSTPOINT)
        Workflow2Definition.objects.create(
            name="TP device created",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=YAML_TRUSTPOINT,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

    @override_settings(WORKFLOWS2_RUN_MODE="sync")
    def test_creating_device_triggers_workflow_sync(self) -> None:
        self._store_definition()
        self.assertEqual(Workflow2Instance.objects.count(), 0)

        DeviceModel.objects.create(
            common_name="dev1",
            serial_number="SN-1",
        )

        self.assertEqual(Workflow2Instance.objects.count(), 1)
        inst = Workflow2Instance.objects.first()
        assert inst is not None
        self.assertEqual(inst.definition.name, "TP device created")
        self.assertEqual(inst.status, Workflow2Instance.STATUS_STOPPED)

    @override_settings(WORKFLOWS2_RUN_MODE="db")
    def test_creating_device_triggers_workflow_db(self) -> None:
        self._store_definition()
        self.assertEqual(Workflow2Instance.objects.count(), 0)

        DeviceModel.objects.create(
            common_name="dev1",
            serial_number="SN-1",
        )

        self.assertEqual(Workflow2Instance.objects.count(), 1)
        inst = Workflow2Instance.objects.first()
        assert inst is not None
        self.assertEqual(inst.status, Workflow2Instance.STATUS_QUEUED)
        self.assertEqual(Workflow2Job.objects.filter(instance=inst, status=Workflow2Job.STATUS_QUEUED).count(), 1)

        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id="test-worker")
        worker.tick()

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_STOPPED)
