# workflows2/catalog/presets.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

InsertKind = Literal["inline", "block"]


@dataclass(frozen=True)
class Preset:
    id: str
    title: str
    description: str
    insert_kind: InsertKind
    snippet: str
    areas: set[str]
    triggers: set[str] | None = None
    step_types: set[str] | None = None


PRESETS: list[Preset] = [
    # ----- top-level -----
    Preset(
        id="trigger_block",
        title="Trigger block",
        description="Insert a full trigger block skeleton.",
        insert_kind="block",
        snippet=(
            "trigger:\n"
            "  on: __TRIGGER_KEY__\n"
            "  sources:\n"
            "    trustpoint: true\n"
            "    ca_ids: []\n"
            "    domain_ids: []\n"
            "    device_ids: []\n"
        ),
        areas={"root"},
    ),
    Preset(
        id="apply_exists_item",
        title="Apply: exists condition",
        description="Insert an apply list item using exists.",
        insert_kind="block",
        snippet="- exists: ${event.__CURSOR__}\n",
        areas={"apply", "root"},
    ),
    Preset(
        id="apply_compare_item",
        title="Apply: compare condition",
        description="Insert an apply list item using compare.",
        insert_kind="block",
        snippet=(
            "- compare:\n"
            "    left: ${vars.__CURSOR__}\n"
            "    op: \"==\"\n"
            "    right: 0\n"
        ),
        areas={"apply", "root"},
    ),
    Preset(
        id="workflow_skeleton",
        title="Workflow skeleton",
        description="Insert minimal workflow skeleton (start/steps/flow).",
        insert_kind="block",
        snippet=(
            "workflow:\n"
            "  start: __STEP_NAME__\n"
            "  steps:\n"
            "    __STEP_NAME__:\n"
            "      type: set\n"
            "      vars:\n"
            "        example: \"__CURSOR__\"\n"
            "  flow:\n"
            "    - from: __STEP_NAME__\n"
            "      to: __STEP_ID_2__\n"
        ),
        areas={"root"},
    ),
    Preset(
        id="workflow_start_line",
        title="Workflow: start line",
        description="Insert or update workflow.start line.",
        insert_kind="block",
        snippet="start: __STEP_NAME__\n",
        areas={"workflow", "workflow.start"},
    ),

    # ----- flow helpers -----
    Preset(
        id="flow_linear_edge",
        title="Flow: linear edge",
        description="Insert a linear flow edge.",
        insert_kind="block",
        snippet="- from: __FROM_STEP__\n  to: __TO_STEP__\n",
        areas={"workflow.flow"},
    ),
    Preset(
        id="flow_outcome_edge",
        title="Flow: outcome edge",
        description="Insert an outcome-based flow edge.",
        insert_kind="block",
        snippet="- from: __FROM_STEP__\n  on: __OUTCOME__\n  to: __TO_STEP__\n",
        areas={"workflow.flow"},
    ),


]
