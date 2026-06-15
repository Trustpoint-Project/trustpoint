from __future__ import annotations

from datetime import timedelta
import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from management.models.workflows2 import WorkflowExecutionConfig
from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.models import (
    Workflow2Approval,
    Workflow2Definition,
    Workflow2Instance,
    Workflow2Job,
    Workflow2Run,
    Workflow2StepRun,
    Workflow2WorkerHeartbeat,
)
from workflows2.services.dispatch import EventSource, WorkflowDispatchService


GRAPH_YAML = """\
schema: trustpoint.workflow.v2
name: Graph API Example
enabled: true

trigger:
  on: workflows2.test
  sources:
    trustpoint: true

workflow:
  start: decide

  steps:
    decide:
      type: logic
      cases:
        - when:
            exists: ${event.device}
          outcome: ok
      default: reject

    stop_ok:
      type: set
      vars: {}

    mark_rejected:
      type: set_status
      status: rejected
      reason: graph_rejected

  flow:
    - from: decide
      on: ok
      to: stop_ok
    - from: decide
      on: reject
      to: mark_rejected
"""


APPROVAL_CONTINUE_YAML = """\
schema: trustpoint.workflow.v2
name: Approval Continue Example
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
      rejected_outcome: needs_review
      timeout_seconds: 3600

    mark_review:
      type: set
      vars:
        result: reviewed

  flow:
    - from: approve
      on: needs_review
      to: mark_review
"""


class Workflow2HttpViewTests(TestCase):
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_user(
            username="workflow2-tester",
            password="testpass123",
        )

    def _store_definition(self) -> Workflow2Definition:
        ir = compile_workflow_yaml(GRAPH_YAML, compiler_version="test")
        return Workflow2Definition.objects.create(
            name="Graph API Example",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=GRAPH_YAML,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

    def _store_approval_definition(self) -> Workflow2Definition:
        ir = compile_workflow_yaml(APPROVAL_CONTINUE_YAML, compiler_version="test")
        return Workflow2Definition.objects.create(
            name="Approval Continue Example",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=APPROVAL_CONTINUE_YAML,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

    def test_context_catalog_requires_login(self) -> None:
        response = self.client.get(reverse("workflows2:context_catalog"))
        self.assertEqual(response.status_code, 302)

    def test_context_catalog_includes_trigger_source_lists(self) -> None:
        self.client.force_login(self.user)

        response = self.client.get(reverse("workflows2:context_catalog"))
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertIn("trigger_sources", payload)
        self.assertEqual(sorted(payload["trigger_sources"].keys()), ["cas", "devices", "domains"])
        self.assertIsInstance(payload["trigger_sources"]["cas"], list)
        self.assertIsInstance(payload["trigger_sources"]["domains"], list)
        self.assertIsInstance(payload["trigger_sources"]["devices"], list)

    def test_context_catalog_includes_grouped_searchable_event_metadata(self) -> None:
        self.client.force_login(self.user)

        response = self.client.get(reverse("workflows2:context_catalog"))
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        by_key = {event["key"]: event for event in payload["events"]}

        self.assertIn("device.updated", by_key)
        self.assertEqual(by_key["device.updated"]["group"], "device_lifecycle")
        self.assertEqual(by_key["device.updated"]["group_title"], "Device lifecycle")
        self.assertIn("device updated", by_key["device.updated"]["search_text"])
        self.assertIn("device lifecycle", by_key["device.updated"]["search_text"])
        self.assertNotIn("before", by_key["device.updated"]["search_text"])

        self.assertIn("certificate.issued", by_key)
        self.assertEqual(by_key["certificate.issued"]["group"], "certificate_lifecycle")
        self.assertEqual(by_key["certificate.issued"]["group_title"], "Certificate lifecycle")
        self.assertIn("certificate issued", by_key["certificate.issued"]["search_text"])
        self.assertNotIn("managed credential", by_key["certificate.issued"]["search_text"])

        self.assertIn("guide_trigger_search_placeholder", payload["meta"]["i18n"])

    def test_trigger_catalog_endpoint_includes_enriched_new_triggers(self) -> None:
        self.client.force_login(self.user)

        response = self.client.get(reverse("workflows2:api_triggers"))
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        by_key = {event["key"]: event for event in payload["events"]}

        self.assertEqual(by_key["device.updated"]["group_title"], "Device lifecycle")
        self.assertEqual(by_key["certificate.revoked"]["group_title"], "Certificate lifecycle")
        self.assertEqual(by_key["cmp.initialization"]["group_title"], "CMP")
        self.assertEqual(by_key["cmp.certification"]["group_title"], "CMP")
        self.assertEqual(by_key["est.simpleenroll"]["group_title"], "EST")
        self.assertEqual(by_key["rest.enroll"]["group_title"], "REST")
        self.assertIn("cmp", by_key["cmp.initialization"]["search_text"])
        self.assertIn("est", by_key["est.simpleenroll"]["search_text"])

    def test_runs_list_requires_login(self) -> None:
        response = self.client.get(reverse("workflows2:runs-list"))
        self.assertEqual(response.status_code, 302)

    def test_definition_create_uses_yaml_name_and_form_enabled_flag(self) -> None:
        self.client.force_login(self.user)

        yaml_text = """\
schema: trustpoint.workflow.v2
name: YAML Name
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

        response = self.client.post(
            reverse("workflows2:definitions_new"),
            {
                "enabled": "",
                "yaml_text": yaml_text,
            },
        )

        self.assertEqual(response.status_code, 302)

        definition = Workflow2Definition.objects.latest("created_at")
        self.assertEqual(definition.name, "YAML Name")
        self.assertFalse(definition.enabled)
        self.assertIn("name: YAML Name", definition.yaml_text)
        self.assertIn("enabled: false", definition.yaml_text)
        self.assertEqual(definition.ir_json["name"], "YAML Name")
        self.assertFalse(definition.ir_json["enabled"])

    def test_runs_list_hides_unsupported_legacy_run_status(self) -> None:
        self.client.force_login(self.user)
        run = Workflow2Run.objects.create(
            trigger_on="est.simpleenroll",
            event_json={"est": {"operation": "simpleenroll"}},
            source_json={},
            status="no_match",
            finalized=True,
        )

        response = self.client.get(reverse("workflows2:runs-list"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, str(run.id))
        self.assertNotContains(response, "No-match trigger attempts are hidden by default.")
        self.assertNotContains(response, "Include no-match runs")

        detail_response = self.client.get(reverse("workflows2:runs-detail", args=[run.id]))
        self.assertEqual(detail_response.status_code, 404)

    def test_definition_graph_endpoint_uses_service_shape(self) -> None:
        definition = self._store_definition()
        self.client.force_login(self.user)

        response = self.client.get(reverse("workflows2:api_definition_graph", args=[definition.id]))
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        node_ids = {node["id"] for node in payload["nodes"]}

        self.assertFalse(any(node_id.startswith("$") for node_id in node_ids))
        self.assertIn("stop_ok", node_ids)
        self.assertIn("mark_rejected", node_ids)
        self.assertEqual(payload["definition_id"], str(definition.id))
        self.assertEqual(payload["ir_hash"], definition.ir_hash)

    def test_graph_from_yaml_endpoint_requires_login(self) -> None:
        response = self.client.post(
            reverse("workflows2:api_graph_from_yaml"),
            data=json.dumps({"yaml_text": GRAPH_YAML}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 302)

    def test_graph_from_yaml_endpoint_returns_real_terminal_nodes(self) -> None:
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("workflows2:api_graph_from_yaml"),
            data=json.dumps({"yaml_text": GRAPH_YAML}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        node_ids = {node["id"] for node in payload["nodes"]}

        self.assertFalse(any(node_id.startswith("$") for node_id in node_ids))
        self.assertIn("stop_ok", node_ids)
        self.assertIn("mark_rejected", node_ids)

    def test_approval_resolve_continues_inline_when_no_worker_is_present(self) -> None:
        self.client.force_login(self.user)

        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.INLINE
        cfg.save()

        self._store_approval_definition()
        svc = WorkflowDispatchService()
        with self.captureOnCommitCallbacks(execute=True):
            instances = svc.emit_event(
                on="workflows2.test",
                event={"device": {"id": "dev-1"}},
                source=EventSource(trustpoint=True),
            )

        inst = instances[0]
        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_AWAITING)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("workflows2:approvals-resolve", args=[approval.id]),
                {"decision": "rejected", "comment": "Needs review"},
            )

        self.assertEqual(response.status_code, 302)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_FINISHED)
        self.assertEqual(inst.vars_json.get("result"), "reviewed")
        self.assertEqual(
            Workflow2Job.objects.filter(instance=inst, status=Workflow2Job.STATUS_QUEUED).count(),
            0,
        )

    def test_approval_resolve_auto_mode_continues_inline_when_worker_heartbeat_is_stale(self) -> None:
        self.client.force_login(self.user)

        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.AUTO
        cfg.worker_stale_after_seconds = 30
        cfg.save()

        stale_time = timezone.now() - timedelta(seconds=31)
        Workflow2WorkerHeartbeat.objects.create(worker_id="stale-worker", last_seen=stale_time)

        self._store_approval_definition()
        svc = WorkflowDispatchService()
        with self.captureOnCommitCallbacks(execute=True):
            instances = svc.emit_event(
                on="workflows2.test",
                event={"device": {"id": "dev-1"}},
                source=EventSource(trustpoint=True),
            )

        inst = instances[0]
        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_AWAITING)

        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("workflows2:approvals-resolve", args=[approval.id]),
                {"decision": "rejected", "comment": "Needs review"},
            )

        self.assertEqual(response.status_code, 302)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_FINISHED)
        self.assertEqual(inst.vars_json.get("result"), "reviewed")
        self.assertEqual(
            Workflow2Job.objects.filter(instance=inst, status=Workflow2Job.STATUS_QUEUED).count(),
            0,
        )

    def test_web_request_drains_queued_backlog_when_auto_detects_no_worker(self) -> None:
        self.client.force_login(self.user)

        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.WORKER
        cfg.save()

        self._store_definition()
        svc = WorkflowDispatchService()
        inst = svc.emit_event(
            on="workflows2.test",
            event={"device": {"id": "dev-1"}},
            source=EventSource(trustpoint=True),
        )[0]

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_QUEUED)

        cfg.mode = WorkflowExecutionConfig.Mode.AUTO
        cfg.worker_stale_after_seconds = 30
        cfg.save()

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.get(reverse("workflows2:runs-list"))

        self.assertEqual(response.status_code, 200)
        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_FINISHED)
        self.assertEqual(Workflow2Job.objects.filter(status=Workflow2Job.STATUS_QUEUED).count(), 0)

    def test_detail_pages_render_for_run_instance_and_approval(self) -> None:
        self.client.force_login(self.user)

        cfg = WorkflowExecutionConfig.load()
        cfg.mode = WorkflowExecutionConfig.Mode.INLINE
        cfg.save()

        self._store_approval_definition()
        svc = WorkflowDispatchService()
        with self.captureOnCommitCallbacks(execute=True):
            instances = svc.emit_event(
                on="workflows2.test",
                event={"device": {"id": "dev-1", "common_name": "Router-01"}},
                source=EventSource(trustpoint=True, domain_id=123, device_id="dev-1"),
            )

        inst = instances[0]
        approval = Workflow2Approval.objects.get(instance=inst, step_id="approve")

        run_response = self.client.get(reverse("workflows2:runs-detail", args=[inst.run_id]))
        self.assertEqual(run_response.status_code, 200)
        self.assertContains(run_response, "Workflow instances")

        instance_response = self.client.get(reverse("workflows2:instances-detail", args=[inst.id]))
        self.assertEqual(instance_response.status_code, 200)
        self.assertContains(instance_response, "Execution timeline")

        approval_response = self.client.get(reverse("workflows2:approvals-detail", args=[approval.id]))
        self.assertEqual(approval_response.status_code, 200)
        self.assertContains(approval_response, "Approval review")

    def test_waiting_list_includes_approvals_paused_instances_and_errors(self) -> None:
        self.client.force_login(self.user)

        definition = self._store_approval_definition()
        run = Workflow2Run.objects.create(
            trigger_on="workflows2.test",
            event_json={"device": {"id": "dev-1"}},
            source_json={"trustpoint": True},
            status=Workflow2Run.STATUS_AWAITING,
            finalized=False,
        )
        awaiting = Workflow2Instance.objects.create(
            run=run,
            definition=definition,
            event_json={},
            vars_json={},
            status=Workflow2Instance.STATUS_AWAITING,
            current_step="approve",
        )
        Workflow2Approval.objects.create(
            instance=awaiting,
            step_id="approve",
            status=Workflow2Approval.STATUS_PENDING,
            expires_at=timezone.now() + timedelta(hours=1),
        )
        Workflow2Instance.objects.create(
            run=run,
            definition=definition,
            event_json={},
            vars_json={},
            status=Workflow2Instance.STATUS_PAUSED,
            current_step="mark_review",
            status_message="Waiting for operator resume",
        )
        Workflow2Instance.objects.create(
            run=run,
            definition=definition,
            event_json={},
            vars_json={},
            status=Workflow2Instance.STATUS_ERROR,
            current_step="approve",
            status_message="Notification backend failed",
        )

        response = self.client.get(reverse("workflows2:approvals-list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["summary_total"], 3)
        self.assertEqual(response.context["summary_pending_approvals"], 1)
        self.assertEqual(response.context["summary_paused_instances"], 1)
        self.assertEqual(response.context["summary_error_instances"], 1)
        self.assertEqual(
            {row["kind"] for row in response.context["waiting_rows"]},
            {"approval", "paused", "error"},
        )
        approval_row = next(row for row in response.context["waiting_rows"] if row["kind"] == "approval")
        self.assertEqual(approval_row["detail"], "Decision required")
        self.assertContains(response, "Expires:")
        self.assertContains(response, "Waiting for operator resume")
        self.assertContains(response, "Notification backend failed")

    def test_waiting_list_kind_filter_shows_only_paused_instances(self) -> None:
        self.client.force_login(self.user)

        definition = self._store_definition()
        run = Workflow2Run.objects.create(
            trigger_on="workflows2.test",
            event_json={},
            source_json={"trustpoint": True},
            status=Workflow2Run.STATUS_PAUSED,
            finalized=False,
        )
        Workflow2Instance.objects.create(
            run=run,
            definition=definition,
            event_json={},
            vars_json={},
            status=Workflow2Instance.STATUS_PAUSED,
            current_step="decide",
            status_message="Paused on purpose",
        )
        Workflow2Instance.objects.create(
            run=run,
            definition=definition,
            event_json={},
            vars_json={},
            status=Workflow2Instance.STATUS_ERROR,
            current_step="decide",
            status_message="Should be hidden by the filter",
        )

        response = self.client.get(reverse("workflows2:approvals-list"), {"kind": "paused", "sort": "bad-sort"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["kind"], "paused")
        self.assertEqual(response.context["sort"], "created")
        self.assertEqual([row["kind"] for row in response.context["waiting_rows"]], ["paused"])
        self.assertContains(response, "Paused on purpose")
        self.assertNotContains(response, "Should be hidden by the filter")

    def test_stop_error_instance_preserves_error_context(self) -> None:
        self.client.force_login(self.user)

        definition = self._store_definition()
        run = Workflow2Run.objects.create(
            trigger_on="workflows2.test",
            event_json={"device": {"id": "dev-1"}},
            source_json={"trustpoint": True},
            status=Workflow2Run.STATUS_ERROR,
            finalized=False,
        )
        inst = Workflow2Instance.objects.create(
            run=run,
            definition=definition,
            event_json={"device": {"id": "dev-1"}},
            vars_json={},
            status=Workflow2Instance.STATUS_ERROR,
            current_step="decide",
            status_reason="runtime_error",
            status_message="ValueError: bad route",
            run_count=1,
        )
        Workflow2StepRun.objects.create(
            instance=inst,
            run_index=1,
            step_id="decide",
            step_type="logic",
            status="error",
            error="ValueError: bad route",
            vars_delta={},
            output=None,
            created_at=timezone.now(),
        )
        Workflow2Job.objects.create(
            instance=inst,
            kind=Workflow2Job.KIND_RUN,
            status=Workflow2Job.STATUS_QUEUED,
        )

        response = self.client.post(reverse("workflows2:instances-stop", args=[inst.id]))

        self.assertEqual(response.status_code, 302)

        inst.refresh_from_db()
        self.assertEqual(inst.status, Workflow2Instance.STATUS_STOPPED)
        self.assertEqual(inst.status_reason, "stopped_after_error")
        self.assertEqual(inst.status_message, "ValueError: bad route")
        self.assertEqual(inst.current_step, "")
        self.assertEqual(
            Workflow2Job.objects.get(instance=inst).status,
            Workflow2Job.STATUS_CANCELLED,
        )

        run.refresh_from_db()
        self.assertEqual(run.status, Workflow2Run.STATUS_STOPPED)
        self.assertTrue(run.finalized)

    def test_release_run_idempotency_view_allows_same_request_again(self) -> None:
        self.client.force_login(self.user)

        run = Workflow2Run.objects.create(
            trigger_on="workflows2.test",
            event_json={"device": {"common_name": "device-a"}},
            source_json={"trustpoint": True},
            idempotency_key="same-request",
            status=Workflow2Run.STATUS_REJECTED,
            finalized=True,
        )

        response = self.client.post(reverse("workflows2:runs-release-idempotency", args=[run.id]))

        self.assertEqual(response.status_code, 302)

        run.refresh_from_db()
        self.assertEqual(run.idempotency_key, "")
        self.assertEqual(run.idempotency_released_key, "same-request")
        self.assertEqual(run.idempotency_release_mode, "manual")
        self.assertEqual(run.idempotency_released_by, self.user.get_username())
        self.assertIsNotNone(run.idempotency_released_at)

    def test_runs_list_searches_workflow_definition_and_event_payload(self) -> None:
        self.client.force_login(self.user)

        definition = self._store_definition()
        matching_run = Workflow2Run.objects.create(
            trigger_on="workflows2.test",
            event_json={"device": {"common_name": "alpha-device"}},
            source_json={"trustpoint": True},
            status=Workflow2Run.STATUS_REJECTED,
            finalized=True,
            idempotency_released_key="manual-key",
            idempotency_release_mode="manual",
            idempotency_released_at=timezone.now(),
        )
        Workflow2Instance.objects.create(
            run=matching_run,
            definition=definition,
            event_json={},
            vars_json={},
            status=Workflow2Instance.STATUS_REJECTED,
        )
        Workflow2Run.objects.create(
            trigger_on="workflows2.test",
            event_json={"device": {"common_name": "other-device"}},
            source_json={"trustpoint": True},
            status=Workflow2Run.STATUS_FINISHED,
            finalized=True,
        )

        response = self.client.get(
            reverse("workflows2:runs-list"),
            {"q": "alpha-device", "idempotency": "manual"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, str(matching_run.id))
        self.assertContains(response, "Released manually")
        self.assertNotContains(response, "other-device")
