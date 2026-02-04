from django.test import TestCase

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance
from workflows2.services.runtime import WorkflowRuntimeService


SIMPLE_YAML = """
schema: trustpoint.workflow.v2
name: Persist test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: stop_now

  steps:
    stop_now:
      type: stop
      reason: done

  flow: []
"""


class PersistenceTests(TestCase):
    def test_instance_is_persisted_and_stopped(self) -> None:
        ir = compile_workflow_yaml(SIMPLE_YAML)

        definition = Workflow2Definition.objects.create(
            name="Persist test",
            enabled=True,
            yaml_text=SIMPLE_YAML,
            ir_json=ir,
            ir_hash="dummy",
        )

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        instance = runtime.create_instance(
            definition=definition,
            event={"device": {"id": "x"}},
        )

        instance = runtime.run_instance(instance)

        self.assertEqual(instance.status, Workflow2Instance.STATUS_STOPPED)
        self.assertEqual(instance.run_count, 1)
        self.assertEqual(instance.runs.count(), 1)

        run = instance.runs.first()
        assert run is not None
        self.assertEqual(run.step_id, "stop_now")
        self.assertEqual(run.status, "stopped")
