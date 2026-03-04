from __future__ import annotations

import json

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from workflows2.compiler.compiler import WorkflowCompiler
from workflows2.services.graph import WorkflowGraphService


@method_decorator(csrf_exempt, name="dispatch")
class Workflow2GraphFromYamlView(View):
    """
    Compile raw YAML and return the same graph structure
    as Workflow2DefinitionGraphView, but without persisting anything.
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
            # Compile YAML → IR
            compiler = WorkflowCompiler()
            compiled = compiler.compile_text(yaml_text)  # adjust if your API differs
            ir = compiled.ir  # adjust if your compiler returns dict directly

            # Reuse same graph adapter via service
            svc = WorkflowGraphService()
            graph = svc.adapter.to_graph(ir)

            return JsonResponse(graph)

        except Exception as e:
            # Optional: catch your CompileError separately if you have one
            return JsonResponse(
                {"error": f"{type(e).__name__}: {str(e)}"},
                status=400,
            )
