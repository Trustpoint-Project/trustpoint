from __future__ import annotations

import json
from typing import Any

from django.db import transaction

from workflows.models import WorkflowInstance
from workflows.services.executors.factory import NodeExecutorFactory
from workflows.services.types import ExecStatus, NodeResult
from workflows.services.context import compact_context_blob, VARS_MAX_BYTES


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
    steps = inst.get_steps()
    cur = inst.get_current_step_index()
    return max(0, len(steps) - (cur + 1))


def _deep_merge_no_overwrite(dst: dict[str, Any], src: dict[str, Any]) -> None:
    """Deep-merge src into dst. If a leaf exists with a different non-dict value, raise ValueError."""
    for k, v in src.items():
        if k not in dst:
            dst[k] = v
            continue
        dv = dst[k]
        if isinstance(dv, dict) and isinstance(v, dict):
            _deep_merge_no_overwrite(dv, v)
            continue
        if dv != v:
            raise ValueError(f'ctx.vars collision at key "{k}": {dv!r} vs {v!r}')


def _size_bytes(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False))


def advance_instance(inst: WorkflowInstance, signal: str | None = None) -> None:
    """Advance an instance until WAITING or a terminal outcome is reached."""
    with transaction.atomic():
        # Lock row to avoid concurrent advances
        inst = WorkflowInstance.objects.select_for_update().get(pk=inst.pk)

        if inst.finalized:
            return

        if inst.state == WorkflowInstance.STATE_STARTING:
            inst.state = WorkflowInstance.STATE_RUNNING
            inst.save(update_fields=['state'])

        budget = _max_pass_hops(inst) + 1
        for _ in range(budget):
            node_meta = _current_node(inst)
            node_type = str(node_meta.get('type', ''))

            executor = NodeExecutorFactory.create(node_type)
            result: NodeResult = executor.execute(inst, signal)

            # Persist per-step context (compacted)
            if result.context is not None:
                sc = dict(inst.step_contexts or {})
                sc[str(inst.current_step)] = compact_context_blob(dict(result.context))
                inst.step_contexts = sc
                inst.save(update_fields=['step_contexts'])

            # Merge vars into global $vars (with collision/size guard)
            if result.vars:
                sc = dict(inst.step_contexts or {})
                vars_map = dict(sc.get('$vars') or {})
                _deep_merge_no_overwrite(vars_map, dict(result.vars))
                if _size_bytes(vars_map) > VARS_MAX_BYTES:
                    # Hard fail on overflow
                    inst.state = WorkflowInstance.STATE_FAILED
                    inst.finalize()
                    inst.save(update_fields=['state', 'finalized'])
                    break
                sc['$vars'] = vars_map
                inst.step_contexts = sc
                inst.save(update_fields=['step_contexts'])

            status = result.status

            if status == ExecStatus.PASSED:
                if _advance_pointer(inst):
                    signal = None  # consume one-shot signals
                    continue
                inst.state = WorkflowInstance.STATE_COMPLETED
                inst.finalize()
                inst.save(update_fields=['state', 'finalized'])
                break

            if status == ExecStatus.WAITING:
                # Central policy: Approval waits in AwaitingApproval; other nodes keep Running.
                inst.state = (
                    WorkflowInstance.STATE_AWAITING if node_type == 'Approval'
                    else WorkflowInstance.STATE_RUNNING
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

            # Defensive fallback
            inst.state = WorkflowInstance.STATE_FAILED
            inst.finalize()
            inst.save(update_fields=['state', 'finalized'])
            break
