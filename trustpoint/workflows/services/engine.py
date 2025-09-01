# workflows/services/engine.py
from __future__ import annotations

from typing import Any

from django.db import transaction

from workflows.models import WorkflowInstance
from workflows.services.executors.factory import NodeExecutorFactory
from workflows.services.types import ExecStatus, NodeResult


def _current_node(inst: WorkflowInstance) -> dict[str, Any]:
    for n in inst.get_steps():
        if n['id'] == inst.current_step:
            return n
    msg = f'Unknown current_step {inst.current_step!r}'
    raise ValueError(msg)


def _advance_pointer(inst: WorkflowInstance) -> bool:
    nxt = inst.get_next_step()
    if nxt:
        inst.current_step = nxt
        inst.state = WorkflowInstance.STATE_RUNNING
        inst.save(update_fields=['current_step', 'state'])
        return True
    return False


def _max_pass_hops(inst: WorkflowInstance) -> int:
    """Maximum number of PASS transitions we can make in this advancement.

    Each PASSED must move to the next node. So the theoretical upper bound is
    the number of nodes remaining from the current position.
    """
    steps = inst.get_steps()
    cur = inst.get_current_step_index()
    # Remaining “edges” to traverse from current node to end
    return max(0, len(steps) - (cur + 1))


def advance_instance(inst: WorkflowInstance, signal: str | None = None) -> None:
    """Advance an instance until a WAIT or a terminal outcome is reached."""
    with transaction.atomic():
        # Lock row to avoid concurrent advances
        inst = WorkflowInstance.objects.select_for_update().get(pk=inst.pk)

        if inst.finalized:
            return

        if inst.state == WorkflowInstance.STATE_STARTING:
            inst.state = WorkflowInstance.STATE_RUNNING
            inst.save(update_fields=['state'])

        # We can make at most “remaining nodes” PASS hops in this call.
        budget = _max_pass_hops(inst) + 1  # +1 lets the last node return COMPLETED
        for _ in range(budget):
            node_meta = _current_node(inst)
            node_type = node_meta.get('type', 'error')

            executor = NodeExecutorFactory.create(node_type)
            result: NodeResult = executor.execute(inst, signal)

            if result.context is not None:
                sc = dict(inst.step_contexts or {})
                sc[str(inst.current_step)] = dict(result.context)
                inst.step_contexts = sc
                inst.save(update_fields=['step_contexts'])

            status = result.status

            if status == ExecStatus.PASSED:
                if _advance_pointer(inst):
                    signal = None  # one-shot signals
                    continue
                inst.state = WorkflowInstance.STATE_COMPLETED
                inst.finalize()
                inst.save(update_fields=['state', 'finalized'])
                break

            if status == ExecStatus.WAITING:
                inst.state = result.wait_state or (
                    WorkflowInstance.STATE_AWAITING if node_type == 'Approval' else WorkflowInstance.STATE_RUNNING
                )
                inst.save(update_fields=['state'])
                break

            if status == ExecStatus.APPROVED:
                inst.state = WorkflowInstance.STATE_APPROVED
                inst.save(update_fields=['state'])
                break

            if status == ExecStatus.REJECTED:
                inst.state = WorkflowInstance.STATE_REJECTED
                inst.save(update_fields=['state'])
                break

            if status == ExecStatus.COMPLETED:
                inst.state = WorkflowInstance.STATE_COMPLETED
                inst.finalize()
                inst.save(update_fields=['state', 'finalized'])
                break

            if status == ExecStatus.FAIL:
                inst.state = WorkflowInstance.STATE_FAILED
                inst.finalize()
                inst.save(update_fields=['state', 'finalized'])
                break

            # Defensive fallback (should never happen)
            inst.state = WorkflowInstance.STATE_FAILED
            inst.finalize()
            inst.save(update_fields=['state', 'finalized'])
            break
