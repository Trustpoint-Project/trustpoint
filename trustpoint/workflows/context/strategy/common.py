"""Shared context catalog groups used by multiple strategies.

The functions in this module return UI-oriented variable groups for the wizard.
"""

from __future__ import annotations

from typing import Any


def common_workflow_group(_instance: Any = None) -> dict[str, Any]:
    """Return the common workflow variable group.

    Args:
        _instance: Optional instance parameter (unused; kept for API compatibility).

    Returns:
        A dict describing a wizard variable group for workflow metadata.
    """
    return {
        'name': 'Workflow',
        'vars': [
            {'path': 'ctx.workflow.id', 'label': 'Workflow ID', 'sample': None},
            {'path': 'ctx.workflow.name', 'label': 'Workflow Name', 'sample': None},
        ],
    }


def common_instance_group(_instance: Any = None) -> dict[str, Any]:
    """Return the common workflow instance variable group.

    Args:
        _instance: Optional instance parameter (unused; kept for API compatibility).

    Returns:
        A dict describing a wizard variable group for instance metadata.
    """
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
