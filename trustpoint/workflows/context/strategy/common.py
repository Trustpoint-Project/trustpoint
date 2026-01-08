# workflows/context/strategy/common.py

from __future__ import annotations

from typing import Any


def common_workflow_group(_instance: Any = None) -> dict[str, Any]:
    return {
        'name': 'Workflow',
        'vars': [
            {'path': 'ctx.workflow.id', 'label': 'Workflow ID', 'sample': None},
            {'path': 'ctx.workflow.name', 'label': 'Workflow Name', 'sample': None},
        ],
    }


def common_instance_group(_instance: Any = None) -> dict[str, Any]:
    return {
        'name': 'Instance',
        'vars': [
            # Align with runtime context.py (ctx.instance.state)
            {'path': 'ctx.instance.state', 'label': 'Instance State', 'sample': None},
            {'path': 'ctx.instance.id', 'label': 'Instance ID', 'sample': None},
            {'path': 'ctx.instance.current_step', 'label': 'Current Step', 'sample': None},
            {'path': 'ctx.instance.created_at', 'label': 'Instance Created At', 'sample': None},
            {'path': 'ctx.instance.updated_at', 'label': 'Instance Updated At', 'sample': None},
        ],
    }
