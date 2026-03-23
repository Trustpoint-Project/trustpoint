from __future__ import annotations

import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.views import View

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.services.graph import WorkflowGraphService


class Workflow2GraphFromYamlView(LoginRequiredMixin, View):
    """
    Compile raw YAML and return the same graph structure as the saved-definition
    graph endpoint, but without persisting anything.
    """

    def post(self, request, *args, **kwargs):
        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON body"}, status=400)

        yaml_text = payload.get("yaml_text", "")
        if not isinstance(yaml_text, str) or not yaml_text.strip():
            return JsonResponse({"error": "yaml_text missing"}, status=400)

        try:
            ir = compile_workflow_yaml(yaml_text, compiler_version="workflows2-graph-api")
            graph = WorkflowGraphService().graph_from_ir(ir=ir)
            return JsonResponse(graph)

        except Exception as e:
            return JsonResponse(
                {"error": f"{type(e).__name__}: {str(e)}"},
                status=400,
            )
