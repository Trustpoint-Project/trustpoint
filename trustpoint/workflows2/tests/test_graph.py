from __future__ import annotations

from django.test import TestCase
from django.contrib.auth import get_user_model

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.models import Workflow2Definition

User = get_user_model()


YAML_OK = """
schema: trustpoint.workflow.v2
name: Graph test
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: a

  steps:
    a:
      type: set
      vars:
        foo: bar

    b:
      type: logic
      cases:
        - when:
            exists: ${event.device}
          outcome: ok
      default: fail

    ok_end:
      type: stop
      reason: Done

    fail_end:
      type: stop
      reason: Fail

  flow:
    - from: a
      to: b
    - from: b
      on: ok
      to: ok_end
    - from: b
      on: fail
      to: fail_end
"""


class GraphEndpointTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(username="u1", password="pw")  # type: ignore[arg-type]
        self.client.login(username="u1", password="pw")

    def test_graph_endpoint_returns_nodes_and_edges(self) -> None:
        ir = compile_workflow_yaml(YAML_OK)

        d = Workflow2Definition.objects.create(
            name="Graph test",
            enabled=True,
            trigger_on=ir["trigger"]["on"],
            yaml_text=YAML_OK,
            ir_json=ir,
            ir_hash=ir["meta"]["ir_hash"],
        )

        resp = self.client.get(f"/workflows2/api/definitions/{d.id}/graph/")
        self.assertEqual(resp.status_code, 200)

        data = resp.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)

        node_ids = {n["id"] for n in data["nodes"]}
        self.assertTrue({"a", "b", "ok_end", "fail_end"}.issubset(node_ids))

        # Check we have outcome edges
        edges = data["edges"]
        outcome_edges = [e for e in edges if e["from"] == "b" and e["on"] in ("ok", "fail")]
        self.assertEqual(len(outcome_edges), 2)
