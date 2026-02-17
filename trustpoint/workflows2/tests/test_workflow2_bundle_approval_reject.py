from __future__ import annotations

from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Definition, Workflow2Instance, Workflow2Job, Workflow2Run
from workflows2.services.dispatch import EventSource, WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


YAML_APPROVAL_REJECT = """
schema: trustpoint.workflow.v2
name: Approval Reject Test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: approve

  steps:
    approve:
      type: approval
      approved_outcome: approved
      rejected_outcome: rejected
      timeout_seconds: 3600

    ok:
      type: succeed
      message: ok

    no:
      type: reject
      reason: "Denied"

  flow:
    - from: approve
      on: approved
      to: ok
    - from: approve
      on: rejected
      to: no
"""


YAML_TWO_WORKFLOWS = """
schema: trustpoint.workflow.v2
name: Two Workflows Gate Test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: done
  steps:
    done:
      type: succeed
      message: ok
  flow: []
"""


class Workflow2BundleApprovalRejectTests(TestCase):
    def _store_def(self, yaml_text: str, *, name: str) -> Workflow2Definition:
        ir = compile_workflow_yaml(yaml_text)
        return Workflow2Definition.objects.create(
            name=name,
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=yaml_text,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

    def test_reject_step_sets_instance_rejected(self) -> None:
        d = self._store_def(YAML_APPROVAL_REJECT, name="A")
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())

        inst = runtime.create_instance(definition=d, event={"device": {"id": "x"}})
        # run first step -> awaiting (approval)
        runtime.run_one_step(inst)
        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_AWAITING)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")
        runtime.resolve_approval(approval=approval, decision="rejected")

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_RUNNING)

        # next run step should execute "no" reject step
        runtime.run_one_step(inst)
        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_REJECTED)

    @override_settings(WORKFLOWS2_RUN_MODE="db")
    def test_dispatch_creates_run_and_instances_and_awaits(self) -> None:
        self._store_def(YAML_APPROVAL_REJECT, name="A")

        svc = WorkflowDispatchService()
        instances = svc.emit_event(
            on="device.created",
            event={"device": {"common_name": "dev1"}},
            source=EventSource(trustpoint=True),
            idempotency_key="k1",
        )
        self.assertEqual(len(instances), 1)

        inst = instances[0]
        self.assertIsNotNone(inst.run_id)

        run = Workflow2Run.objects.get(id=inst.run_id)
        self.assertEqual(run.status, Workflow2Run.STATUS_QUEUED)  # jobs queued, not executed yet
        self.assertEqual(Workflow2Job.objects.filter(instance=inst, status=Workflow2Job.STATUS_QUEUED).count(), 1)

        # worker executes one step -> awaiting
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id="t")
        stats = worker.tick()
        self.assertEqual(stats.claimed, 1)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_AWAITING)

        run.refresh_from_db()
        self.assertEqual(run.status, Workflow2Run.STATUS_AWAITING)

    def test_get_or_create_run_idempotency_returns_same_run(self) -> None:
        self._store_def(YAML_TWO_WORKFLOWS, name="A")
        svc = WorkflowDispatchService()

        a = svc.emit_event(
            on="device.created",
            event={"x": 1},
            source=EventSource(trustpoint=True),
            idempotency_key="same",
        )
        b = svc.emit_event(
            on="device.created",
            event={"x": 1},
            source=EventSource(trustpoint=True),
            idempotency_key="same",
        )
        self.assertEqual(len(a), len(b))
        self.assertEqual(a[0].run_id, b[0].run_id)

    def test_worker_cancels_on_expired_lease(self) -> None:
        d = self._store_def(YAML_TWO_WORKFLOWS, name="A")
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())

        inst = runtime.create_instance(definition=d, event={"device": {"id": "x"}})
        job = Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_RUNNING,
            locked_until=timezone.now() - timedelta(seconds=1),
            locked_by="crashed-worker",
        )

        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=1, worker_id="new-worker")
        stats = worker.tick()
        self.assertEqual(stats.recovered, 1)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_PAUSED)

        job.refresh_from_db()
        self.assertEqual(job.status, Workflow2Job.STATUS_FAILED)

    def test_run_aggregate_rejected_if_any_rejected(self) -> None:
        d = self._store_def(YAML_APPROVAL_REJECT, name="A")
        svc = WorkflowDispatchService(executor=WorkflowExecutor())
        run = svc.get_or_create_run(
            on="device.created",
            event={"device": {"id": "x"}},
            source=EventSource(trustpoint=True),
            idempotency_key="agg",
        )

        runtime = svc.runtime
        inst = runtime.create_instance(run=run, definition=d, event={"device": {"id": "x"}})

        # run approval awaiting
        runtime.run_one_step(inst)
        run.refresh_from_db()
        self.assertEqual(run.status, Workflow2Run.STATUS_AWAITING)

        # reject
        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")
        runtime.resolve_approval(approval=approval, decision="rejected")

        # execute reject step
        runtime.run_one_step(inst)
        run.refresh_from_db()
        self.assertEqual(run.status, Workflow2Run.STATUS_REJECTED)
