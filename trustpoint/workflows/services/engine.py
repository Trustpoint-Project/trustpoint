"""Workflow engine: advancing instances through their nodes."""

from __future__ import annotations

from typing import Any

from workflows.models import WorkflowInstance
from workflows.services.executors.factory import NodeExecutorFactory
from workflows.services.types import ExecStatus, NodeResult


def _current_node(instance: WorkflowInstance) -> dict[str, Any]:
    """Return the current node metadata by id."""
    for n in instance.get_steps():
        if n['id'] == instance.current_step:
            return n
    msg = f'Unknown current_step {instance.current_step!r}'
    raise ValueError(msg)


def _advance_pointer(instance: WorkflowInstance) -> bool:
    """Move to the next node if any; set state=Running; persist. Return True if advanced."""
    nxt = instance.get_next_step()
    if nxt:
        instance.current_step = nxt
        instance.state = WorkflowInstance.STATE_RUNNING
        instance.save(update_fields=['current_step', 'state'])
        return True
    return False


def _persist_step_context(instance: WorkflowInstance, result: NodeResult) -> None:
    """Persist per-step context if provided by the executor."""
    if result.context is None:
        return
    sc = dict(instance.step_contexts or {})
    sc[str(instance.current_step)] = dict(result.context)
    instance.step_contexts = sc
    instance.save(update_fields=['step_contexts'])


def _handle_passed(instance: WorkflowInstance) -> bool:
    """Handle ExecStatus.PASSED. Return True if engine should continue looping."""
    if _advance_pointer(instance):
        return True  # continue with next node in same call
    instance.finalize(WorkflowInstance.STATE_COMPLETED)
    return False


def _handle_waiting(instance: WorkflowInstance, node_type: str, wait_state: str | None) -> None:
    """Handle ExecStatus.WAITING by pausing the instance."""
    default_wait = WorkflowInstance.STATE_AWAITING if node_type == 'Approval' else WorkflowInstance.STATE_RUNNING
    instance.state = wait_state or default_wait
    instance.save(update_fields=['state'])


def _handle_terminal(instance: WorkflowInstance, status: ExecStatus) -> None:
    """Handle terminal statuses (APPROVED/REJECTED/COMPLETED/FAIL)."""
    if status is ExecStatus.APPROVED:
        # terminal approved - do not finalize; caller (EST view) may issue and then finalize
        instance.state = WorkflowInstance.STATE_APPROVED
        instance.save(update_fields=['state'])
    elif status is ExecStatus.REJECTED:
        # terminal rejected - do not finalize; caller may finalize
        instance.state = WorkflowInstance.STATE_REJECTED
        instance.save(update_fields=['state'])
    elif status is ExecStatus.COMPLETED:
        instance.finalize(WorkflowInstance.STATE_COMPLETED)
    elif status is ExecStatus.FAIL:
        instance.finalize(WorkflowInstance.STATE_FAILED)
    else:
        # Defensive fallback
        instance.finalize(WorkflowInstance.STATE_FAILED)


def advance_instance(instance: WorkflowInstance, signal: str | None = None) -> None:
    """Advance a workflow run until it must pause or reach a terminal outcome.

    The engine advances through nodes until one of the following occurs:
      • a node returns WAITING  -> pause (e.g., Approval),
      • a node returns terminal -> stop (APPROVED/REJECTED/COMPLETED/FAIL),
      • or there are no more nodes -> COMPLETE + finalize.

    Notes:
      - APPROVED: engine does not finalize (caller may issue and then finalize).
      - REJECTED: engine does not finalize (caller may finalize).
      - COMPLETED/FAIL: engine finalizes immediately.
    """
    if instance.finalized:
        return

    # Kick off brand-new runs
    if instance.state == WorkflowInstance.STATE_STARTING:
        instance.state = WorkflowInstance.STATE_RUNNING
        instance.save(update_fields=['state'])

    # Safety ceiling (prevents accidental infinite progress)
    steps_len = len(instance.get_steps())
    guard = steps_len + 8

    for _ in range(guard):
        node_meta = _current_node(instance)
        node_type = node_meta.get('type', '')

        executor = NodeExecutorFactory.create(node_type)
        result: NodeResult = executor.execute(instance, signal)

        _persist_step_context(instance, result)

        status = result.status

        if status is ExecStatus.PASSED:
            if _handle_passed(instance):
                signal = None  # one-shot
                continue
            break

        if status is ExecStatus.WAITING:
            _handle_waiting(instance, node_type, result.wait_state)
            break

        _handle_terminal(instance, status)
        break
