"""Workflow engine: advance instances step-by-step until WAITING or terminal."""
from __future__ import annotations

import json
from typing import Any, cast

from django.db import transaction

from workflows.models import EnrollmentRequest, State, WorkflowInstance
from workflows.services.context import VARS_MAX_BYTES, compact_context_blob
from workflows.services.executors.factory import StepExecutorFactory
from workflows.services.types import ExecutorResult


def _current_step(inst: WorkflowInstance) -> dict[str, Any]:
    for step in inst.get_steps():
        if step['id'] == inst.current_step:
            return step
    raise ValueError(f'Unknown current_step {inst.current_step!r}')


def _advance_pointer(inst: WorkflowInstance) -> bool:
    nxt = inst.get_next_step()
    if nxt:
        inst.current_step = nxt
        inst.state = WorkflowInstance.STATE_RUNNING
        inst.save(update_fields=['current_step', 'state'])
        return True
    return False


def _max_pass_hops(inst: WorkflowInstance) -> int:
    """Upper bound of PASS transitions from current step."""
    steps = inst.get_steps()
    cur = inst.get_current_step_index()
    return max(0, len(steps) - (cur + 1))


def _size_bytes(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False))


def _deep_merge_no_overwrite(dst: dict[str, Any], src: dict[str, Any]) -> None:
    """Deep-merge src into dst; if a leaf exists with a different value, raise ValueError."""
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


def advance_instance(inst: WorkflowInstance, signal: str | None = None) -> None:
    """Advance an instance until AWAITING or a terminal outcome is reached.

    Rules:
      - Executors return ExecutorResult(status, context?, vars?).
      - Engine stores compacted per-step context.
      - Engine merges ExecutorResult.vars into global $vars (no overwrite of different values).
      - Size guard on $vars (VARS_MAX_BYTES).
      - State.APPROVED acts like PASSED if there is a next step; becomes terminal only at the end.
    """
    with transaction.atomic():
        inst = WorkflowInstance.objects.select_for_update().get(pk=inst.pk)

        if inst.finalized:
            return

        budget = _max_pass_hops(inst) + 1
        for _ in range(budget):
            step_meta = _current_step(inst)
            step_type = str(step_meta.get('type') or '')

            executor = StepExecutorFactory.create(step_type)
            result: ExecutorResult = executor.execute(inst, signal)

            # Persist step context (compacted)
            if result.context is not None:
                sc = dict(inst.step_contexts or {})
                sc[str(inst.current_step)] = compact_context_blob(dict(result.context))
                inst.step_contexts = sc
                inst.save(update_fields=['step_contexts'])

            # Merge vars into global $vars
            if result.vars and isinstance(result.vars, dict):
                sc = dict(inst.step_contexts or {})
                vars_map = dict(sc.get('$vars') or {})
                _deep_merge_no_overwrite(vars_map, dict(result.vars))
                if _size_bytes(vars_map) > VARS_MAX_BYTES:
                    inst.state = WorkflowInstance.STATE_FAILED
                    inst.save(update_fields=['state'])
                    break
                sc['$vars'] = vars_map
                inst.step_contexts = sc
                inst.save(update_fields=['step_contexts'])

            status = result.status

            # === PASS / APPROVED with continuation semantics ==================
            if status == State.PASSED:
                if _advance_pointer(inst):
                    signal = None
                    continue
                inst.state = WorkflowInstance.STATE_PASSED
                inst.save(update_fields=['state'])
                break

            if status == State.APPROVED:
                if _advance_pointer(inst):
                    signal = None
                    continue
                inst.state = WorkflowInstance.STATE_APPROVED
                inst.save(update_fields=['state'])
                break

            # === AWAITING (pause until next signal) ===========================
            if status == State.AWAITING:
                inst.state = WorkflowInstance.STATE_AWAITING
                inst.save(update_fields=['state'])
                break

            # === Terminal outcomes ============================================
            if status == State.REJECTED:
                inst.state = WorkflowInstance.STATE_REJECTED
                inst.save(update_fields=['state'])
                break

            if status == State.FINALIZED:
                inst.state = WorkflowInstance.STATE_FINALIZED
                inst.finalize()
                inst.save(update_fields=['state'])
                break

            if status == State.FAILED:
                inst.state = WorkflowInstance.STATE_FAILED
                inst.save(update_fields=['state'])
                break

            # Defensive fallback
            inst.state = WorkflowInstance.STATE_FAILED
            inst.save(update_fields=['state'])
            break
