# workflows2/services/graph.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from workflows2.models import Workflow2Definition, Workflow2Instance, Workflow2StepRun


@dataclass(frozen=True)
class GraphNode:
    id: str
    type: str
    title: str | None
    produces_outcome: bool
    outcomes: list[str]
    is_terminal: bool


@dataclass(frozen=True)
class GraphEdge:
    frm: str
    to: str
    on: str | None  # outcome name or None for linear edges


class IRGraphAdapter:
    """
    Convert compiled IR into a UI-friendly graph representation.

    - Derived from IR (YAML stays source of truth).
    - No layout in v1.
    """

    def __init__(self, *, terminal_types: set[str] | None = None) -> None:
        # use compiler's terminal set by default
        self.terminal_types = terminal_types or {"stop", "succeed", "fail", "reject"}

    def to_graph(self, ir: dict[str, Any]) -> dict[str, Any]:
        wf = self._get_dict(ir, "workflow")
        steps = self._get_dict(wf, "steps")
        transitions = self._get_dict(wf, "transitions")

        edges = self._build_edges(transitions)

        # compute which nodes have outgoing edges
        has_outgoing: set[str] = {e.frm for e in edges}

        nodes: list[GraphNode] = []
        for step_id, s in steps.items():
            if not isinstance(step_id, str) or not isinstance(s, dict):
                continue

            typ = s.get("type")
            if not isinstance(typ, str):
                typ = "unknown"

            title = s.get("title")
            if title is not None and not isinstance(title, str):
                title = None

            produces = bool(s.get("produces_outcome", False))

            outcomes_raw = s.get("outcomes") or []
            outcomes: list[str] = [o for o in outcomes_raw if isinstance(o, str)]

            # NEW:
            # terminal if:
            # - it's an explicit terminal type OR
            # - it has no outgoing edges (implicit end node)
            is_terminal = (typ in self.terminal_types) or (step_id not in has_outgoing)

            nodes.append(
                GraphNode(
                    id=step_id,
                    type=typ,
                    title=title,
                    produces_outcome=produces,
                    outcomes=outcomes,
                    is_terminal=is_terminal,
                )
            )

        nodes.sort(key=lambda n: n.id)

        start = wf.get("start")
        if not isinstance(start, str) or not start:
            start = None

        return {
            "ir_version": ir.get("ir_version"),
            "name": ir.get("name"),
            "enabled": bool(ir.get("enabled", True)),
            "start": start,
            "nodes": [n.__dict__ for n in nodes],
            "edges": [{"from": e.frm, "to": e.to, "on": e.on} for e in edges],
        }

    @staticmethod
    def _get_dict(obj: Any, key: str) -> dict[str, Any]:
        if not isinstance(obj, dict):
            return {}
        v = obj.get(key)
        return v if isinstance(v, dict) else {}

    def _build_nodes(self, steps: dict[str, Any]) -> list[GraphNode]:
        out: list[GraphNode] = []
        for step_id, s in steps.items():
            if not isinstance(step_id, str) or not isinstance(s, dict):
                continue

            typ = s.get("type")
            if not isinstance(typ, str):
                typ = "unknown"

            title = s.get("title")
            if title is not None and not isinstance(title, str):
                title = None

            produces = bool(s.get("produces_outcome", False))

            outcomes_raw = s.get("outcomes") or []
            outcomes: list[str] = [o for o in outcomes_raw if isinstance(o, str)]

            out.append(
                GraphNode(
                    id=step_id,
                    type=typ,
                    title=title,
                    produces_outcome=produces,
                    outcomes=outcomes,
                    is_terminal=(typ in self.terminal_types),
                )
            )

        out.sort(key=lambda n: n.id)
        return out

    def _build_edges(self, transitions: dict[str, Any]) -> list[GraphEdge]:
        out: list[GraphEdge] = []
        for frm, tr in transitions.items():
            if not isinstance(frm, str) or not isinstance(tr, dict):
                continue

            kind = tr.get("kind")
            if kind == "linear":
                to = tr.get("to")
                if isinstance(to, str):
                    out.append(GraphEdge(frm=frm, to=to, on=None))
                continue

            if kind == "by_outcome":
                m = tr.get("map")
                if not isinstance(m, dict):
                    continue
                for outcome, to in m.items():
                    if isinstance(outcome, str) and isinstance(to, str):
                        out.append(GraphEdge(frm=frm, to=to, on=outcome))
                continue

        out.sort(key=lambda e: (e.frm, "" if e.on is None else e.on, e.to))
        return out


class WorkflowGraphService:
    """
    Model-aware helpers for Flow UI:
    - definition_graph(definition) -> nodes/edges derived from IR
    - instance_overlay(instance) -> per-step status overlay derived from StepRun history
    """

    def __init__(self) -> None:
        self.adapter = IRGraphAdapter()

    def definition_graph(self, *, definition: Workflow2Definition) -> dict[str, Any]:
        base = self.adapter.to_graph(definition.ir_json or {})
        base["definition_id"] = str(definition.id)
        base["ir_hash"] = definition.ir_hash
        return base

    def instance_overlay(self, *, instance: Workflow2Instance) -> dict[str, Any]:
        runs = list(
            Workflow2StepRun.objects.filter(instance=instance)
            .order_by("run_index")
            .only("step_id", "status", "outcome", "error", "run_index", "step_type", "next_step")
        )

        per_step: dict[str, dict[str, Any]] = {}
        for r in runs:
            per_step[r.step_id] = {
                "last_run_index": r.run_index,
                "status": r.status,
                "outcome": r.outcome,
                "error": r.error,
                "step_type": r.step_type,
                "next_step": r.next_step,
            }

        return {
            "instance_id": str(instance.id),
            "definition_id": str(instance.definition_id),
            "instance_status": instance.status,
            "current_step": instance.current_step,
            "run_count": instance.run_count,
            "steps": per_step,
        }
