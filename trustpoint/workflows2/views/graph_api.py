from __future__ import annotations

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View

from workflows2.models import Workflow2Definition


class Workflow2DefinitionGraphView(View):
    def get(self, request, *args, **kwargs):
        # Accept either kwarg name (prevents “unexpected pk” issues)
        definition_id = kwargs.get("definition_id") or kwargs.get("pk")
        definition = get_object_or_404(Workflow2Definition, id=definition_id)

        # You said you already have this graph JSON shape; if you have a service, call it here.
        # For now: assume `definition.ir_json` is already compiled and your existing
        # graph builder exists. If you DO already have a graph builder, replace the block below.
        ir = definition.ir_json or {}
        wf = (ir.get("workflow") or {}) if isinstance(ir, dict) else {}
        steps = wf.get("steps") or {}
        transitions = wf.get("transitions") or {}
        start = wf.get("start")

        nodes = []
        if isinstance(steps, dict):
            for step_id, step in steps.items():
                if not isinstance(step, dict):
                    continue
                nodes.append(
                    {
                        "id": step_id,
                        "type": step.get("type"),
                        "title": step.get("title"),
                        "produces_outcome": bool(step.get("produces_outcome")),
                        "outcomes": step.get("outcomes") or [],
                        "is_terminal": bool(step.get("type") in {"stop", "succeed", "fail", "reject"}),
                    }
                )

        edges = []
        if isinstance(transitions, dict):
            for from_id, t in transitions.items():
                if not isinstance(t, dict):
                    continue
                kind = t.get("kind")
                if kind == "linear":
                    to = t.get("to")
                    if isinstance(to, str) and to:
                        edges.append({"from": from_id, "to": to, "on": None})
                elif kind == "by_outcome":
                    m = t.get("map") or {}
                    if isinstance(m, dict):
                        for outcome, to in m.items():
                            if isinstance(to, str) and to:
                                edges.append({"from": from_id, "to": to, "on": str(outcome)})

        data = {
            "ir_version": ir.get("ir_version", "v2"),
            "name": definition.name,
            "enabled": definition.enabled,
            "start": start,
            "nodes": nodes,
            "edges": edges,
            "definition_id": str(definition.id),
            "ir_hash": getattr(definition, "ir_hash", "") or "",
        }
        return JsonResponse(data)
