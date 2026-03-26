from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from management.models.workflows2 import WorkflowExecutionConfig
from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2Job, Workflow2Run
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

YAML_APPLY_FILTERED = """
schema: trustpoint.workflow.v2
name: Filtered workflow
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

apply:
  - compare:
      left: ${event.device.common_name}
      op: "=="
      right: "router-01"

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
        with self.captureOnCommitCallbacks(execute=True):
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

    def test_dispatch_skips_definition_when_apply_conditions_do_not_match(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.QUEUE
        cfg.save()

        ir = compile_workflow_yaml(YAML_APPLY_FILTERED)
        Workflow2Definition.objects.create(
            name="Filtered workflow",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=YAML_APPLY_FILTERED,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

        svc = WorkflowDispatchService()
        instances = svc.emit_event(
            on="device.created",
            event={"device": {"common_name": "switch-02"}},
            source=EventSource(trustpoint=True),
        )

        self.assertEqual(instances, [])
        run = Workflow2Run.objects.latest("created_at")
        self.assertEqual(run.status, Workflow2Run.STATUS_NO_MATCH)

    def test_dispatch_uses_compiled_enabled_state_as_runtime_source_of_truth(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.QUEUE
        cfg.save()

        disabled_yaml = YAML_TRUSTPOINT.replace("enabled: true", "enabled: false", 1)
        ir = compile_workflow_yaml(disabled_yaml)
        Workflow2Definition.objects.create(
            name="Disabled in IR",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=disabled_yaml,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

        svc = WorkflowDispatchService()
        instances = svc.emit_event(
            on="device.created",
            event={"device": {"common_name": "dev1"}},
            source=EventSource(trustpoint=True),
        )

        self.assertEqual(instances, [])
        run = Workflow2Run.objects.latest("created_at")
        self.assertEqual(run.status, Workflow2Run.STATUS_NO_MATCH)

    def test_workflow2run_unique_idempotency_constraint_rejects_duplicate_non_empty_key(self) -> None:
        Workflow2Run.objects.create(
            trigger_on="device.created",
            event_json={"x": 1},
            source_json={"trustpoint": True},
            idempotency_key="same-key",
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Workflow2Run.objects.create(
                    trigger_on="device.created",
                    event_json={"x": 2},
                    source_json={"trustpoint": True},
                    idempotency_key="same-key",
                )

    def test_workflow2run_unique_idempotency_constraint_allows_blank_keys(self) -> None:
        Workflow2Run.objects.create(
            trigger_on="device.created",
            event_json={"x": 1},
            source_json={"trustpoint": True},
            idempotency_key="",
        )
        Workflow2Run.objects.create(
            trigger_on="device.created",
            event_json={"x": 2},
            source_json={"trustpoint": True},
            idempotency_key="",
        )

        self.assertEqual(
            Workflow2Run.objects.filter(trigger_on="device.created", idempotency_key="").count(),
            2,
        )

    def test_emit_event_outcome_returns_exact_run_from_dispatch_call(self) -> None:
        definition = self._store_definition()
        now = timezone.now()

        expected_run = Workflow2Run.objects.create(
            trigger_on="device.created",
            event_json={"x": 1},
            source_json={"trustpoint": True},
            idempotency_key="",
            status=Workflow2Run.STATUS_SUCCEEDED,
            finalized=True,
            created_at=now,
        )
        expected_instance = Workflow2Instance.objects.create(
            definition=definition,
            run=expected_run,
            event_json={"x": 1},
            vars_json={},
            status=Workflow2Instance.STATUS_SUCCEEDED,
        )

        Workflow2Run.objects.create(
            trigger_on="device.created",
            event_json={"x": 2},
            source_json={"trustpoint": True},
            idempotency_key="",
            status=Workflow2Run.STATUS_FAILED,
            finalized=True,
            created_at=now + timedelta(seconds=1),
        )

        svc = WorkflowDispatchService()
        with patch.object(
            WorkflowDispatchService,
            "_emit_event_internal",
            return_value=(expected_run, [expected_instance]),
        ):
            outcome = svc.emit_event_outcome(
                on="device.created",
                event={"device": {"common_name": "dev1"}},
                source=EventSource(trustpoint=True),
            )

        self.assertEqual(outcome.run.id, expected_run.id)
        self.assertEqual(outcome.instances[0].run_id, expected_run.id)
        self.assertEqual(outcome.status, "completed")
