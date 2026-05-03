# workflows2/tests/test_persistence.py
from __future__ import annotations

from django.test import TestCase

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2StepRun
from workflows2.services.runtime import WorkflowRuntimeService


SIMPLE_YAML = """\
schema: trustpoint.workflow.v2
name: Persistence test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: stop_now
  steps:
    stop_now:
      type: set
      vars: {}
  flow: []
"""


class PersistenceTests(TestCase):
    def test_instance_is_persisted_and_stopped(self) -> None:
        ir = compile_workflow_yaml(SIMPLE_YAML, compiler_version="test")
        d = Workflow2Definition.objects.create(
            name="Persistence test",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=SIMPLE_YAML,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        inst = runtime.create_instance(definition=d, event={"device": {"common_name": "dev1"}})

        inst = runtime.run_instance(inst)
        inst.refresh_from_db()

        self.assertEqual(inst.status, Workflow2Instance.STATUS_SUCCEEDED)
        self.assertEqual(inst.current_step, '')
        self.assertEqual(inst.run_count, 1)

        runs = list(Workflow2StepRun.objects.filter(instance=inst).order_by("run_index"))
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].step_id, "stop_now")
        self.assertEqual(runs[0].status, "ok")
        self.assertEqual(runs[0].next_step, '')
