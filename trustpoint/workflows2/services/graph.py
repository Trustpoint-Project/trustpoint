from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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

    Design:
      - UI uses this to render nodes and edges (diagram-js, etc.)
      - YAML stays source-of-truth; graph is derived from IR
      - No positions/layout in v1
    """

    TERMINAL_TYPES: set[str] = {"stop"}

    def to_graph(self, ir: dict[str, Any]) -> dict[str, Any]:
        wf = self._get_dict(ir, "workflow")
        steps = self._get_dict(wf, "steps")
        transitions = self._get_dict(wf, "transitions")

        nodes = self._build_nodes(steps)
        edges = self._build_edges(transitions)

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

    # -------------------- internals -------------------- #

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
                    is_terminal=(typ in self.TERMINAL_TYPES),
                )
            )

        # stable order for diff-friendly responses
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

            # unknown kinds ignored (should not happen in compiled IR)

        # stable order: from, then on (None last), then to
        out.sort(key=lambda e: (e.frm, "" if e.on is None else e.on, e.to))
        return out
