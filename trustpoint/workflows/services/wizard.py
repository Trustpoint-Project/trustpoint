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
    """Build the full workflow-definition JSON from wizard input.

    Args:
        events: List of items like ``{"protocol": str, "operation": str}``.
        steps: Ordered list of items like ``{"type": str, "params": dict[str, Any]}``.

    Returns:
        A dict with keys:
            - ``events``: the input events as-is.
            - ``steps``: list of steps with auto-generated IDs ``step-1``, ``step-2``, ...
            - ``transitions``: linear transitions wiring each step to the next on signal ``"next"``.
    """
    # 1) Steps with auto IDs step-1, step-2, ...
    steps_list: list[dict[str, Any]] = [
        {
            'id': f'step-{idx}',
            'type': step['type'],
            'params': step.get('params', {}),
        }
        for idx, step in enumerate(steps, start=1)
    ]

    # 2) Linear transitions (perf-friendly list comprehension)
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
