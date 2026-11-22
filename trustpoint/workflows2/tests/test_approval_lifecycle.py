# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for approval lifecycle cleanup and restart."""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Definition, Workflow2Instance, Workflow2Run
from workflows2.services.request_decision import Workflow2RequestDecision, resolve_request_decision
from workflows2.services.runtime import WorkflowRuntimeService, expire_pending_approvals

YAML_APPROVAL = """
schema: trustpoint.workflow.v2
name: Approval lifecycle test
enabled: true

trigger:
  on: workflows2.test
  sources:
    trustpoint: true

workflow:
  start: review
  steps:
    review:
      type: approval
      approved_outcome: approved
      rejected_outcome: rejected
      timeout_seconds: 60
"""


def _definition() -> Workflow2Definition:
    ir = compile_workflow_yaml(YAML_APPROVAL)
    return Workflow2Definition.objects.create(
        name='Approval lifecycle test',
        enabled=True,
        trigger_on=ir['trigger']['on'],
        yaml_text=YAML_APPROVAL,
        ir_json=ir,
        ir_hash=ir['meta']['ir_hash'],
    )


class ApprovalLifecycleTests(TestCase):
    """Approvals must not keep a request waiting after they are cancelled or due."""

    def test_reentering_an_approval_step_resets_the_old_decision(self) -> None:
        """A loop back to an approval step must ask again instead of reusing a rejection."""
        definition = _definition()
        instance = Workflow2Instance.objects.create(
            definition=definition,
            event_json={},
            status=Workflow2Instance.STATUS_AWAITING,
            current_step='review',
        )
        Workflow2Approval.objects.create(
            instance=instance,
            step_id='review',
            status=Workflow2Approval.STATUS_REJECTED,
            decided_at=timezone.now(),
        )

        approval = WorkflowRuntimeService(executor=WorkflowExecutor())._ensure_approval(  # noqa: SLF001
            instance=instance,
            step_id='review',
        )

        assert approval.status == Workflow2Approval.STATUS_PENDING
        assert approval.decided_at is None
        assert approval.expires_at is not None

    def test_expire_pending_approvals_processes_due_rows_without_a_page_view(self) -> None:
        """The worker path expires due approvals even when nobody opens the queue."""
        definition = _definition()
        instance = Workflow2Instance.objects.create(
            definition=definition,
            event_json={},
            status=Workflow2Instance.STATUS_AWAITING,
            current_step='review',
        )
        approval = Workflow2Approval.objects.create(
            instance=instance,
            step_id='review',
            status=Workflow2Approval.STATUS_PENDING,
            expires_at=timezone.now() - timedelta(seconds=1),
        )

        expire_pending_approvals()

        approval.refresh_from_db()
        assert approval.status == Workflow2Approval.STATUS_EXPIRED

    def test_cancelled_run_fails_even_if_a_pending_approval_was_left_behind(self) -> None:
        """A terminal run must not tell the client to keep polling."""
        definition = _definition()
        run = Workflow2Run.objects.create(
            trigger_on='workflows2.test',
            event_json={},
            status=Workflow2Run.STATUS_CANCELLED,
            finalized=True,
        )
        instance = Workflow2Instance.objects.create(
            definition=definition,
            run=run,
            event_json={},
            status=Workflow2Instance.STATUS_CANCELLED,
        )
        Workflow2Approval.objects.create(
            instance=instance,
            step_id='review',
            status=Workflow2Approval.STATUS_PENDING,
        )

        assert resolve_request_decision(run) == Workflow2RequestDecision.FAIL
