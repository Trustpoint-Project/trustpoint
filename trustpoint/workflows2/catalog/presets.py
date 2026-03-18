# workflows2/catalog/presets.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


PresetArea = Literal[
    "root",
    "trigger",
    "apply",
    "workflow",
    "workflow.start",
    "workflow.steps",
    "workflow.flow",
]
PresetOperation = Literal[
    "merge_root",
    "set_value",
    "append_list_item",
]


@dataclass(frozen=True)
class Preset:
    id: str
    title: str
    description: str

    operation: PresetOperation
    payload: Any

    areas: set[PresetArea]
    triggers: set[str] | None = None
    step_types: set[str] | None = None


PRESETS: list[Preset] = [
    Preset(
        id="trigger_block",
        title="Trigger block",
        description="Insert a full trigger block with default sources.",
        operation="merge_root",
        payload={
            "trigger": {
                "on": "device.created",
                "sources": {
                    "trustpoint": True,
                    "ca_ids": [],
                    "domain_ids": [],
                    "device_ids": [],
                },
            }
        },
        areas={"root"},
    ),
    Preset(
        id="apply_exists_item",
        title="Apply: exists condition",
        description="Append an apply rule using exists.",
        operation="append_list_item",
        payload={
            "exists": "${event.device.domain}",
        },
        areas={"apply", "root"},
    ),
    Preset(
        id="apply_compare_item",
        title="Apply: compare condition",
        description="Append an apply rule using compare.",
        operation="append_list_item",
        payload={
            "compare": {
                "left": "${vars.status}",
                "op": "==",
                "right": 0,
            }
        },
        areas={"apply", "root"},
    ),
    Preset(
        id="workflow_skeleton",
        title="Workflow skeleton",
        description="Insert a minimal valid workflow with one set step.",
        operation="merge_root",
        payload={
            "workflow": {
                "start": "set_result",
                "steps": {
                    "set_result": {
                        "type": "set",
                        "title": "Set result",
                        "vars": {
                            "result": "ok",
                        },
                    }
                },
                "flow": [],
            }
        },
        areas={"root"},
    ),
    Preset(
        id="workflow_start_value",
        title="Workflow: start value",
        description="Set workflow.start to a step id.",
        operation="set_value",
        payload="step_id",
        areas={"workflow", "workflow.start"},
    ),
    Preset(
        id="flow_linear_edge",
        title="Flow: linear edge",
        description="Append a linear flow edge.",
        operation="append_list_item",
        payload={
            "from": "step_a",
            "to": "step_b",
        },
        areas={"workflow.flow"},
    ),
    Preset(
        id="flow_outcome_edge",
        title="Flow: outcome edge",
        description="Append an outcome-based flow edge.",
        operation="append_list_item",
        payload={
            "from": "step_a",
            "on": "ok",
            "to": "step_b",
        },
        areas={"workflow.flow"},
    ),
    Preset(
        id="flow_to_end",
        title="Flow: end workflow",
        description='Append a flow edge that ends the workflow via "$end".',
        operation="append_list_item",
        payload={
            "from": "step_a",
            "to": "$end",
        },
        areas={"workflow.flow"},
    ),
    Preset(
        id="flow_to_reject",
        title="Flow: reject workflow",
        description='Append a flow edge that rejects the workflow via "$reject".',
        operation="append_list_item",
        payload={
            "from": "step_a",
            "to": "$reject",
        },
        areas={"workflow.flow"},
    ),
]
