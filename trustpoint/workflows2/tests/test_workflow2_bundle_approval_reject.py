from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from management.models.workflows2 import WorkflowExecutionConfig
from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import (
    Workflow2Approval,
    Workflow2Definition,
    Workflow2Instance,
    Workflow2Job,
    Workflow2Run,
    Workflow2StepRun,
)
from workflows2.services.dispatch import EventSource, WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.worker import Workflow2DbWorker


# Approval is NOT allowed on device.created by policy.
# Therefore these tests use the allow-all test trigger.
YAML_APPROVAL_REJECT = """
schema: trustpoint.workflow.v2
name: Approval Reject Test
enabled: true

trigger:
  on: workflows2.test
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

  flow:
    - from: approve
      on: approved
      to: $end
    - from: approve
      on: rejected
      to: $reject
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
      type: set
      vars: {}
  flow: []
"""


YAML_APPROVAL_CUSTOM_OUTCOMES = """
schema: trustpoint.workflow.v2
name: Approval Custom Outcomes
enabled: true

trigger:
  on: workflows2.test
  sources:
    trustpoint: true

workflow:
  start: approve

  steps:
    approve:
      type: approval
      approved_outcome: continue_ok
      rejected_outcome: needs_review
      timeout_seconds: 3600

    mark_review:
      type: set
      vars:
        review_required: true

  flow:
    - from: approve
      on: continue_ok
      to: $end
    - from: approve
      on: needs_review
      to: mark_review
    - from: mark_review
      to: $end
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

        runtime.run_one_step(inst)
        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_AWAITING)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")

        runtime.resolve_approval(approval=approval, decision="rejected")
        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_REJECTED)

    def test_dispatch_creates_run_and_instances_and_awaits(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.QUEUE
        cfg.save()

        self._store_def(YAML_APPROVAL_REJECT, name="A")

        svc = WorkflowDispatchService()
        instances = svc.emit_event(
            on="workflows2.test",
            event={"device": {"common_name": "dev1"}},
            source=EventSource(trustpoint=True),
            idempotency_key="k1",
        )
        self.assertEqual(len(instances), 1)

        inst = instances[0]
        self.assertIsNotNone(inst.run_id)

        run = Workflow2Run.objects.get(id=inst.run_id)
        self.assertEqual(run.status, Workflow2Run.STATUS_QUEUED)
        self.assertEqual(Workflow2Job.objects.filter(instance=inst, status=Workflow2Job.STATUS_QUEUED).count(), 1)

        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())
        worker = Workflow2DbWorker(runtime=runtime, lease_seconds=5, batch_limit=5, worker_id="t")
        stats = worker.tick()
        self.assertEqual(stats.claimed, 1)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_AWAITING)

        run.refresh_from_db()
        self.assertEqual(run.status, Workflow2Run.STATUS_AWAITING)

    def test_get_or_create_run_idempotency_returns_same_run(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.QUEUE
        cfg.save()

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

    def test_get_or_create_run_idempotency_reuses_finalized_run(self) -> None:
        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.QUEUE
        cfg.save()

        self._store_def(YAML_TWO_WORKFLOWS, name="A")
        svc = WorkflowDispatchService()

        first = svc.emit_event(
            on="device.created",
            event={"x": 1},
            source=EventSource(trustpoint=True),
            idempotency_key="done-key",
        )
        run = Workflow2Run.objects.get(id=first[0].run_id)
        run.finalized = True
        run.status = Workflow2Run.STATUS_SUCCEEDED
        run.save(update_fields=["finalized", "status", "updated_at"])

        second = svc.emit_event(
            on="device.created",
            event={"x": 1},
            source=EventSource(trustpoint=True),
            idempotency_key="done-key",
        )
        self.assertEqual(first[0].run_id, second[0].run_id)

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
            on="workflows2.test",
            event={"device": {"id": "x"}},
            source=EventSource(trustpoint=True),
            idempotency_key="agg",
        )

        runtime = svc.runtime
        inst = runtime.create_instance(run=run, definition=d, event={"device": {"id": "x"}})

        runtime.run_one_step(inst)
        run.refresh_from_db()
        self.assertEqual(run.status, Workflow2Run.STATUS_AWAITING)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")
        runtime.resolve_approval(approval=approval, decision="rejected")

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_REJECTED)

        run.refresh_from_db()
        self.assertEqual(run.status, Workflow2Run.STATUS_REJECTED)

    def test_rejected_decision_uses_configured_outcome_and_continues_when_routed(self) -> None:
        d = self._store_def(YAML_APPROVAL_CUSTOM_OUTCOMES, name="custom-reject")
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())

        inst = runtime.create_instance(definition=d, event={"device": {"id": "x"}})
        runtime.run_one_step(inst)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")
        runtime.resolve_approval(approval=approval, decision="rejected")

        inst.refresh_from_db()
        approval.refresh_from_db()

        self.assertEqual(approval.status, Workflow2Approval.STATUS_REJECTED)
        self.assertEqual(inst.status, Workflow2Instance.STATUS_RUNNING)
        self.assertEqual(inst.current_step, "mark_review")

        continued = Workflow2StepRun.objects.get(instance=inst, run_index=2)
        self.assertEqual(continued.step_id, "approve")
        self.assertEqual(continued.status, "continued")
        self.assertEqual(continued.outcome, "needs_review")
        self.assertEqual(continued.next_step, "mark_review")

    def test_approved_decision_can_end_workflow_without_enqueueing_next_step(self) -> None:
        d = self._store_def(YAML_APPROVAL_CUSTOM_OUTCOMES, name="custom-approve")
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())

        inst = runtime.create_instance(definition=d, event={"device": {"id": "x"}})
        runtime.run_one_step(inst)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")
        runtime.resolve_approval(approval=approval, decision="approved")

        inst.refresh_from_db()
        approval.refresh_from_db()

        self.assertEqual(approval.status, Workflow2Approval.STATUS_APPROVED)
        self.assertEqual(inst.status, Workflow2Instance.STATUS_SUCCEEDED)
        self.assertEqual(inst.current_step, '')

        continued = Workflow2StepRun.objects.get(instance=inst, run_index=2)
        self.assertEqual(continued.step_id, "approve")
        self.assertEqual(continued.status, "succeeded")
        self.assertEqual(continued.outcome, "continue_ok")
        self.assertEqual(continued.next_step, '')

    def test_resolve_approval_persists_comment_and_decider(self) -> None:
        d = self._store_def(YAML_APPROVAL_REJECT, name="approval-metadata")
        runtime = WorkflowRuntimeService(executor=WorkflowExecutor())

        inst = runtime.create_instance(definition=d, event={"device": {"id": "x"}})
        runtime.run_one_step(inst)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")
        runtime.resolve_approval(
            approval=approval,
            decision="approved",
            decided_by="workflow-tester",
            comment="Looks good.",
        )

        approval.refresh_from_db()
        step_run = Workflow2StepRun.objects.get(instance=inst, run_index=2)

        self.assertEqual(approval.decided_by, "workflow-tester")
        self.assertEqual(approval.comment, "Looks good.")
        self.assertEqual(step_run.output["decided_by"], "workflow-tester")
        self.assertEqual(step_run.output["comment"], "Looks good.")
