from __future__ import annotations

from typing import Optional

from workflows.models import WorkflowInstance
from workflows.services.executors import NodeExecutorFactory


def advance_instance(
    instance: WorkflowInstance,
    signal: Optional[str] = None,
) -> None:
    """Drive a WorkflowInstance forward.

    • run nodes until you hit AWAITING, APPROVED, REJECTED, or COMPLETED.
    """
    if instance.finalized:
        return

    # kick off if brand new
    if instance.state == WorkflowInstance.STATE_STARTING:
        instance.state = WorkflowInstance.STATE_RUNNING
        instance.save(update_fields=['state'])

    while True:
        # grab metadata for current node
        nodes = instance.definition.definition.get('nodes', [])
        node_meta = next(n for n in nodes if n['id'] == instance.current_step)

        executor = NodeExecutorFactory.create(node_meta['type'])
        next_step, next_state = executor.execute(instance, signal)

        # apply changes
        instance.current_step = next_step or instance.current_step
        instance.state = next_state
        instance.save(update_fields=['current_step', 'state'])

        # stop on any “pause” state
        if instance.state in {
            WorkflowInstance.STATE_AWAITING,
            WorkflowInstance.STATE_REJECTED,
            WorkflowInstance.STATE_COMPLETED,
        }:
            break

        # clear the signal so it’s only used once
        signal = None
