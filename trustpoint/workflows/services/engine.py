"""Workflow engine: advance instances step-by-step until WAITING or terminal.

Runtime contract:
- A step executor returns an ExecutorResult with a status in workflows.models.State.
- Only PASSED and APPROVED advance the step pointer.
- AWAITING pauses on the current step.
- REJECTED/FAILED/ABORTED/FINALIZED are terminal (engine stops).
- Step context (ExecutorResult.context) is stored under step_contexts[str(current_step)].
- Global vars (ExecutorResult.vars) are merged into step_contexts["$vars"] with a no-overwrite policy.

Engine-owned failure reporting:
- If vars merge fails (collision or oversize), the engine marks the instance FAILED
  and writes a deterministic step context describing the reason.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from django.db import transaction

from workflows.models import State, WorkflowInstance
from workflows.services.context import VARS_MAX_BYTES, compact_context_blob
from workflows.services.executors.factory import StepExecutorFactory

if TYPE_CHECKING:
    from workflows.services.types import ExecutorResult


_TERMINAL_STATES: set[str] = {
    State.REJECTED,
    State.FAILED,
    State.ABORTED,
    State.FINALIZED,
}
_CONTINUE_STATES: set[str] = {
    State.PASSED,
    State.APPROVED,
}


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


def _persist_step_context(inst: WorkflowInstance, ctx: dict[str, Any]) -> None:
    """Persist per-step compacted context."""
    step_contexts = dict(inst.step_contexts or {})
    step_contexts[str(inst.current_step)] = compact_context_blob(dict(ctx))
    inst.step_contexts = step_contexts
    inst.save(update_fields=['step_contexts'])


def _persist_executor_context(inst: WorkflowInstance, result: ExecutorResult) -> None:
    """Persist per-step compacted executor context if present."""
    if result.context is None:
        return
    _persist_step_context(inst, result.context.to_dict())


def _make_engine_error_context(*, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a standardized step context for engine-owned failures."""
    out: dict[str, Any] = {
        'type': 'Engine',
        'status': 'failed',
        'error': message,
        'outputs': {},
    }
    if details:
        out['outputs']['details'] = details
    return out


def _fail_instance(inst: WorkflowInstance) -> None:
    """Mark the instance as FAILED."""
    inst.state = State.FAILED
    inst.save(update_fields=['state'])


def _fail_instance_with_step_context(
    inst: WorkflowInstance,
    *,
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Fail instance and persist an engine-owned error context on the current step."""
    _fail_instance(inst)
    _persist_step_context(inst, _make_engine_error_context(message=message, details=details))


def _merge_global_vars(inst: WorkflowInstance, result: ExecutorResult) -> bool:
    """Merge vars into global $vars with a no-overwrite policy.

    Returns:
        True if processing can continue.
        False if merge failed or vars exceed VARS_MAX_BYTES (instance marked FAILED).
    """
    if not (result.vars and isinstance(result.vars, dict)):
        return True

    step_contexts = dict(inst.step_contexts or {})
    vars_map = dict(step_contexts.get('$vars') or {})

    try:
        _deep_merge_no_overwrite(vars_map, dict(result.vars))
    except ValueError as exc:
        _fail_instance_with_step_context(
            inst,
            message='Global vars merge failed (collision).',
            details={'reason': str(exc)},
        )
        return False

    size = _size_bytes(vars_map)
    if size > VARS_MAX_BYTES:
        _fail_instance_with_step_context(
            inst,
            message='Global vars exceeded maximum size.',
            details={'bytes': size, 'max_bytes': VARS_MAX_BYTES},
        )
        return False

    step_contexts['$vars'] = vars_map
    inst.step_contexts = step_contexts
    inst.save(update_fields=['step_contexts'])
    return True


def _recompute_parent(inst: WorkflowInstance) -> None:
    if inst.enrollment_request:
        inst.enrollment_request.recompute_and_save()
    elif inst.device_request:
        inst.device_request.recompute_and_save()


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

            try:
                result: ExecutorResult = executor.execute(inst, signal)
            except Exception as exc:  # noqa: BLE001
                # Executor crashed: fail instance and record error deterministically.
                _fail_instance_with_step_context(
                    inst,
                    message='Executor raised an exception.',
                    details={'step_type': step_type, 'exception': str(exc)},
                )
                _recompute_parent(inst)
                break

            # Persist executor-produced context (if any) before any engine-owned failures.
            _persist_executor_context(inst, result)

            # Vars merge may fail the instance deterministically and record a reason.
            if not _merge_global_vars(inst, result):
                _recompute_parent(inst)
                break

            # Store the resulting state from the executor.
            inst.state = result.status
            inst.save(update_fields=['state'])

            # Continuation semantics: only PASSED/APPROVED advance.
            if result.status in _CONTINUE_STATES:
                if _advance_pointer(inst):
                    signal = None
                    continue

                # No next step -> keep the status (PASSED/APPROVED) and stop.
                _recompute_parent(inst)
                break

            # Waiting or terminal semantics: do not advance pointer.
            if result.status == State.AWAITING or result.status in _TERMINAL_STATES:
                _recompute_parent(inst)
                break

            # Defensive fallback: unknown status -> fail deterministically.
            _fail_instance_with_step_context(
                inst,
                message='Unknown executor status.',
                details={'status': str(result.status), 'step_type': step_type},
            )
            _recompute_parent(inst)
            break
