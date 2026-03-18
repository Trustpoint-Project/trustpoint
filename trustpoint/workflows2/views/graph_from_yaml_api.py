from __future__ import annotations

import json

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from workflows2.compiler.compiler import WorkflowCompiler
from workflows2.services.graph import WorkflowGraphService


@method_decorator(csrf_exempt, name="dispatch")
class Workflow2GraphFromYamlView(View):
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
            compiler = WorkflowCompiler()
            ir = compiler.compile(yaml_text)

            svc = WorkflowGraphService()

            # Prefer the existing adapter path if present.
            if hasattr(svc, "adapter") and hasattr(svc.adapter, "to_graph"):
                graph = svc.adapter.to_graph(ir)
                return JsonResponse(graph)

            # Fallbacks in case your service exposes a direct helper instead.
            if hasattr(svc, "to_graph"):
                graph = svc.to_graph(ir)
                return JsonResponse(graph)

            if hasattr(svc, "graph_from_ir"):
                graph = svc.graph_from_ir(ir)
                return JsonResponse(graph)

            raise RuntimeError("WorkflowGraphService has no supported graph conversion method")

        except Exception as e:
            return JsonResponse(
                {"error": f"{type(e).__name__}: {str(e)}"},
                status=400,
            )
