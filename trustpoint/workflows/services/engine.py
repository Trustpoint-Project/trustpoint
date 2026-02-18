"""Workflow engine: advance instances step-by-step until WAITING or terminal."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from django.db import transaction

from workflows.models import State, WorkflowInstance
from workflows.services.context import VARS_MAX_BYTES, compact_context_blob
from workflows.services.executors.factory import StepExecutorFactory

if TYPE_CHECKING:
    from workflows.services.types import ExecutorResult


def _current_step(inst: WorkflowInstance) -> dict[str, Any]:
    for step in inst.get_steps():
        if step['id'] == inst.current_step:
            return step
    msg = f'Unknown current_step {inst.current_step!r}'
    raise ValueError(msg)


def _advance_pointer(inst: WorkflowInstance) -> bool:
    nxt = inst.get_next_step()
    if nxt:
        inst.current_step = nxt
        inst.state = State.RUNNING
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
            msg = f'ctx.vars collision at key "{k}": {dv!r} vs {v!r}'
            raise ValueError(msg)


def _persist_step_context(inst: WorkflowInstance, result: ExecutorResult) -> None:
    """Persist per-step compacted context if present."""
    if result.context is None:
        return

    step_contexts = dict(inst.step_contexts or {})
    context = dict(result.context)
    step_contexts[str(inst.current_step)] = compact_context_blob(context)
    inst.step_contexts = step_contexts
    inst.save(update_fields=['step_contexts'])


def _merge_global_vars(inst: WorkflowInstance, result: ExecutorResult) -> bool:
    """Merge vars into global $vars.

    Returns:
        True if processing can continue.
        False if the vars size exceeded VARS_MAX_BYTES (instance is marked FAILED).
    """
    if not (result.vars and isinstance(result.vars, dict)):
        return True

    step_contexts = dict(inst.step_contexts or {})
    vars_map = dict(step_contexts.get('$vars') or {})

    _deep_merge_no_overwrite(vars_map, dict(result.vars))

    if _size_bytes(vars_map) > VARS_MAX_BYTES:
        inst.state = State.FAILED
        inst.save(update_fields=['state'])
        return False

    step_contexts['$vars'] = vars_map
    inst.step_contexts = step_contexts
    inst.save(update_fields=['step_contexts'])
    return True


def _handle_status(
    inst: WorkflowInstance,
    status: State,
    signal: str | None,
) -> tuple[bool, str | None]:
    """Apply status to the instance and decide whether to continue.

    Returns:
        (should_continue, new_signal)
    """
    # default: stop after handling this status; preserve signal
    should_continue = False
    new_signal = signal

    if status in (State.PASSED, State.APPROVED):
        if _advance_pointer(inst):
            # continuation semantics: moved to next step, reset signal
            return True, None
        if status == State.PASSED:
            inst.state = State.PASSED
        else:
            inst.state = State.APPROVED

    elif status == State.AWAITING:
        inst.state = State.AWAITING

    elif status == State.REJECTED:
        inst.state = State.REJECTED

    elif status == State.FINALIZED:
        inst.state = State.FINALIZED
        inst.finalize()

    elif status == State.FAILED:
        inst.state = State.FAILED

    else:
        # Defensive fallback
        inst.state = State.FAILED

    inst.save(update_fields=['state'])
    return should_continue, new_signal


def advance_instance(inst: WorkflowInstance, signal: str | None = None) -> None:
    """Advance an instance until AWAITING or a terminal outcome is reached."""
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
            _persist_step_context(inst, result)
            if inst.enrollment_request:
                inst.enrollment_request.recompute_and_save()

            if not _merge_global_vars(inst, result):
                break

            should_continue, signal = _handle_status(inst, result.status, signal)
            if not should_continue:
                break
