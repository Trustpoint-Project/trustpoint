"""Utilities to transform wizard input into a workflow definition schema.

This module exposes a single helper to convert simple wizard-provided lists
of events and steps into the internal workflow-definition JSON structure.
"""

from __future__ import annotations

from typing import Any


def transform_to_definition_schema(
    events: list[dict[str, str]],
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """Convert wizard input into an internal workflow-definition schema.

    Args:
        events: List of event descriptors, each containing protocol and operation.
        steps: Ordered list of step descriptors, each with type and parameters.

    Returns:
        dict[str, Any]: Workflow definition containing:
            - "events": the input events.
            - "steps": steps with generated IDs ("step-1", "step-2", ...).
            - "transitions": linear transitions linking steps on the "next" signal.
    """
    steps_list: list[dict[str, Any]] = [
        {
            'id': f'step-{idx}',
            'type': step['type'],
            'params': step.get('params', {}),
        }
        for idx, step in enumerate(steps, start=1)
    ]

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
