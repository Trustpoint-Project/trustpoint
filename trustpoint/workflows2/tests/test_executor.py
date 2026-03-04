# workflows2/tests/test_executor.py
from __future__ import annotations

from django.test import SimpleTestCase

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.compiler.errors import CompileError
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
        vars.http_status: status_code

    route_by_status:
      type: logic
      cases:
        - when:
            compare:
              left: ${vars.http_status}
              op: "=="
              right: 200
          outcome: ok
      default: reject

    compute_ok:
      type: compute
      set:
        vars.score: ${add(vars.http_status, 1)}

  flow:
    - from: notify
      to: call_status
    - from: call_status
      to: route_by_status
    - from: route_by_status
      on: ok
      to: compute_ok
    - from: route_by_status
      on: reject
      to: $reject
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
        self.assertEqual(res.status, "succeeded")
        self.assertEqual(res.vars["http_status"], 200)
        self.assertEqual(res.vars["score"], 201)

        self.assertEqual(len(email.sent), 1)
        self.assertIn("dev1", email.sent[0]["subject"])

    def test_reject_path_routes_to_rejected(self) -> None:
        ir = compile_workflow_yaml(YAML, compiler_version="test")
        ex = WorkflowExecutor(email=CapturingEmail(), webhook=FakeWebhook(500))

        res = ex.run(ir, event={"device": {"common_name": "dev1"}}, vars={})
        self.assertEqual(res.status, "rejected")

    def test_missing_outcome_route_is_compile_error(self) -> None:
        bad = YAML.replace(
            "    - from: route_by_status\n      on: ok\n      to: compute_ok\n",
            "",
        )
        with self.assertRaises(CompileError):
            compile_workflow_yaml(bad, compiler_version="test")