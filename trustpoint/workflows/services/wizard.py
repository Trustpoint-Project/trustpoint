"""Utilities to transform wizard input into a workflow definition schema.

This module exposes a single helper to convert simple wizard-provided lists
of triggers and steps into the internal workflow-definition JSON structure.
"""

from __future__ import annotations

from typing import Any


def transform_to_definition_schema(
    triggers: list[dict[str, str]],
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the full workflow-definition JSON from simple wizard input.

    Args:
        triggers: List of items like ``{"protocol": str, "operation": str}``.
        steps: Ordered list of items like ``{"type": str, "params": dict[str, Any]}``.

    Returns:
        A dict with keys:
            - ``triggers``: the input triggers as-is.
            - ``nodes``: list of nodes with auto-generated IDs ``step-1``, ``step-2``, ...
            - ``transitions``: linear transitions wiring each node to the next on signal ``"next"``.
    """
    # 1) Nodes with auto IDs step-1, step-2, ...
    nodes: list[dict[str, Any]] = [
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
            'from': nodes[i]['id'],
            'on': 'next',
            'to': nodes[i + 1]['id'],
        }
        for i in range(len(nodes) - 1)
    ]

    return {
        'triggers': triggers,
        'nodes': nodes,
        'transitions': transitions,
    }
