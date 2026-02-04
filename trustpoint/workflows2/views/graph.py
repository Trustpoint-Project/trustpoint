from __future__ import annotations

from uuid import UUID

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View

from workflows2.models import Workflow2Definition
from workflows2.services.graph import IRGraphAdapter


class Workflow2DefinitionGraphView(LoginRequiredMixin, View):
    """
    GET /workflows2/api/definitions/<uuid>/graph/

    Returns a UI-friendly graph derived from the stored IR.
    """

    def get(self, _request, pk, *_args, **_kwargs):
        try:
            definition = Workflow2Definition.objects.get(pk=pk)
        except Workflow2Definition.DoesNotExist:
            raise Http404

        ir = definition.ir_json
        if not isinstance(ir, dict):
            return JsonResponse({"error": "Invalid IR stored for this definition."}, status=500)

        graph = IRGraphAdapter().to_graph(ir)

        # include small definition metadata for UI convenience
        graph["definition"] = {
            "id": str(definition.id),
            "name": definition.name,
            "enabled": definition.enabled,
            "trigger_on": definition.trigger_on,
            "ir_hash": definition.ir_hash,
        }
        return JsonResponse(graph)



class Workflow2GraphView(LoginRequiredMixin, View):
    """
    Return a minimal graph representation derived from stored IR.
    Used by the diagram-js read-only viewer.
    """

    def get(self, _request: HttpRequest, pk: UUID) -> JsonResponse:
        d = get_object_or_404(Workflow2Definition, pk=pk)

        ir = d.ir_json or {}
        wf = ir.get("workflow") or {}
        steps = wf.get("steps") or {}
        transitions = wf.get("transitions") or {}
        start = wf.get("start")

        nodes = []
        for step_id, s in steps.items():
            nodes.append(
                {
                    "id": step_id,
                    "type": s.get("type"),
                    "title": s.get("title") or step_id,
                    "produces_outcome": bool(s.get("produces_outcome")),
                    "outcomes": list(s.get("outcomes") or []),
                    "is_terminal": (s.get("type") == "stop"),
                }
            )

        edges = []
        for frm, tr in transitions.items():
            kind = tr.get("kind")
            if kind == "linear":
                edges.append(
                    {
                        "id": f"{frm}->__",
                        "from": frm,
                        "to": tr.get("to"),
                        "on": None,
                    }
                )
            elif kind == "by_outcome":
                m = tr.get("map") or {}
                for outcome, to in m.items():
                    edges.append(
                        {
                            "id": f"{frm}--{outcome}-->",
                            "from": frm,
                            "to": to,
                            "on": outcome,
                        }
                    )

        payload = {
            "definition": {
                "id": str(d.id),
                "name": d.name,
                "enabled": bool(d.enabled),
            },
            "start": start,
            "nodes": nodes,
            "edges": edges,
        }
        return JsonResponse(payload, safe=True)
