from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.models import Workflow2Definition


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

  flow:
    - from: decide
      on: ok
      to: $end
    - from: decide
      on: reject
      to: $reject
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

    def test_context_catalog_requires_login(self) -> None:
        response = self.client.get(reverse("workflows2:context_catalog"))
        self.assertEqual(response.status_code, 302)

    def test_runs_list_requires_login(self) -> None:
        response = self.client.get(reverse("workflows2:runs-list"))
        self.assertEqual(response.status_code, 302)

    def test_definition_graph_endpoint_uses_service_shape(self) -> None:
        definition = self._store_definition()
        self.client.force_login(self.user)

        response = self.client.get(reverse("workflows2:api_definition_graph", args=[definition.id]))
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        node_ids = {node["id"] for node in payload["nodes"]}

        self.assertIn("$end", node_ids)
        self.assertIn("$reject", node_ids)
        self.assertEqual(payload["definition_id"], str(definition.id))
        self.assertEqual(payload["ir_hash"], definition.ir_hash)

    def test_graph_from_yaml_endpoint_requires_login(self) -> None:
        response = self.client.post(
            reverse("workflows2:api_graph_from_yaml"),
            data=json.dumps({"yaml_text": GRAPH_YAML}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 302)

    def test_graph_from_yaml_endpoint_returns_virtual_end_nodes(self) -> None:
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("workflows2:api_graph_from_yaml"),
            data=json.dumps({"yaml_text": GRAPH_YAML}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        node_ids = {node["id"] for node in payload["nodes"]}

        self.assertIn("$end", node_ids)
        self.assertIn("$reject", node_ids)
