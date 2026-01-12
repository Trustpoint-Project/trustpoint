"""Utilities to transform wizard input into a workflow definition schema.

This module converts wizard-provided lists of events and steps into the internal
workflow-definition JSON structure persisted in WorkflowDefinition.definition.
"""

from __future__ import annotations

from typing import Any


def transform_to_definition_schema(
    events: list[dict[str, str]],
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """Convert wizard input into an internal workflow-definition schema.

    Rules:
    - Preserve step["id"] if provided and non-empty.
    - Otherwise generate a stable sequential id: "step-<n>".
    - Produce linear transitions in the given order.

    Args:
        events: List of event descriptors.
        steps: Ordered list of step descriptors.

    Returns:
        Workflow definition dict with keys: "events", "steps", "transitions".
    """
    steps_list: list[dict[str, Any]] = []

    for idx, step in enumerate(steps, start=1):
        sid = step.get('id')
        if not isinstance(sid, str) or not sid.strip():
            sid = f'step-{idx}'

        steps_list.append(
            {
                'id': sid,
                'type': step['type'],
                'params': step.get('params', {}) or {},
            }
        )

    transitions: list[dict[str, str]] = [
        {
            'from': steps_list[i]['id'],
            'on': 'next',
            'to': steps_list[i + 1]['id'],
        }
        for i in range(len(steps_list) - 1)
    ]

    return {
        'events': events,
        'steps': steps_list,
        'transitions': transitions,
    }
