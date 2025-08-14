from __future__ import annotations

from typing import Any, Dict, List


def transform_to_definition_schema(
    triggers: List[Dict[str, str]],
    steps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the full workflow-definition JSON from simple wizard input.

    Args:
        triggers: List of {'protocol': str, 'operation': str}.
        steps: Ordered list of {'type': str, 'params': Dict[str,Any]}.

    Returns:
        A dict with keys 'triggers', 'nodes', 'transitions'.
    """
    nodes: List[Dict[str, Any]] = []
    transitions: List[Dict[str, str]] = []

    # 1. Generate nodes with auto IDs step-1, step-2, ...
    for idx, step in enumerate(steps, start=1):
        node_id = f'step-{idx}'
        nodes.append({
            'id': node_id,
            'type': step['type'],
            'params': step.get('params', {}),
        })

    # 2. Wire linear transitions with a default 'next' signal
    for idx in range(len(nodes) - 1):
        transitions.append({
            'from':  nodes[idx]['id'],
            'on':    'next',
            'to':    nodes[idx + 1]['id'],
        })

    return {
        'triggers':    triggers,
        'nodes':       nodes,
        'transitions': transitions,
    }
