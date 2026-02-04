# workflows2/tests/test_executor.py
from __future__ import annotations

from django.test import SimpleTestCase

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.engine.adapters import WebhookResponse
from workflows2.engine.executor import WorkflowExecutor


YAML = """\
schema: trustpoint.workflow.v2
name: Example v2
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true
    ca_ids: []
    domain_ids: []
    device_ids: []

apply:
  - exists: ${event.device}

workflow:
  start: notify

  steps:
    notify:
      type: email
      to: [test.test@gmx.de]
      subject: "New device: ${event.device.common_name}"
      body: "CN=${event.device.common_name}"

    call_status:
      type: webhook
      method: POST
      url: "https://example.com/status"
      capture:
        status_code: vars.http_status

    route_by_status:
      type: logic
      cases:
        - when:
            compare:
              left: ${vars.http_status}
              op: "=="
              right: 200
          outcome: ok
      default: fail

    compute_ok:
      type: compute
      set:
        vars.score: ${add(vars.http_status, 1)}

    stop_ok:
      type: stop
      reason: "Done ok: ${vars.score}"

    stop_fail:
      type: stop
      reason: "Done fail"

  flow:
    - from: notify
      to: call_status
    - from: call_status
      to: route_by_status
    - from: route_by_status
      on: ok
      to: compute_ok
    - from: compute_ok
      to: stop_ok
    - from: route_by_status
      on: fail
      to: stop_fail
"""


class FakeWebhook:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code

    def request(self, *, method: str, url: str, headers: dict[str, str], body, timeout_seconds: int) -> WebhookResponse:
        return WebhookResponse(status_code=self.status_code, body={"ok": True}, headers={"x": "y"})


class CapturingEmail:
    def __init__(self) -> None:
        self.sent = []

    def send(self, *, to, cc, bcc, subject, body) -> None:
        self.sent.append({"to": to, "subject": subject, "body": body})


class ExecutorTests(SimpleTestCase):
    def test_happy_path_routes_ok_and_computes(self) -> None:
        ir = compile_workflow_yaml(YAML, compiler_version="test")
        email = CapturingEmail()
        ex = WorkflowExecutor(email=email, webhook=FakeWebhook(200))

        res = ex.run(ir, event={"device": {"common_name": "dev1"}}, vars={})
        self.assertEqual(res.status, "stopped")
        self.assertEqual(res.vars["http_status"], 200)
        self.assertEqual(res.vars["score"], 201)

        # email step ran
        self.assertEqual(len(email.sent), 1)
        self.assertIn("dev1", email.sent[0]["subject"])

        # stop_ok reason rendered
        self.assertEqual(res.runs[-1].step_type, "stop")
        self.assertIn("201", (res.runs[-1].output or {}).get("reason", ""))

    def test_fail_path_routes_fail(self) -> None:
        ir = compile_workflow_yaml(YAML, compiler_version="test")
        ex = WorkflowExecutor(email=CapturingEmail(), webhook=FakeWebhook(500))

        res = ex.run(ir, event={"device": {"common_name": "dev1"}}, vars={})
        self.assertEqual(res.status, "stopped")
        self.assertEqual(res.runs[-1].step_id, "stop_fail")
