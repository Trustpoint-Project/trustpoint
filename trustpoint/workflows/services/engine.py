"""Workflow engine: advance instances step-by-step until WAITING or terminal.

Runtime contract:
- A step executor returns an ExecutorResult with a status in workflows.models.State.
- Only PASSED and APPROVED advance the step pointer.
- AWAITING pauses on the current step.
- REJECTED/FAILED/ABORTED/FINALIZED are terminal (engine stops).
- Step context (ExecutorResult.context) is stored under step_contexts[str(current_step)].
- Global vars (ExecutorResult.vars) are merged into step_contexts["$vars"].

Engine-owned failure reporting:
- If vars merge fails (collision or oversize), the engine marks the instance FAILED
  and writes a deterministic step context describing the reason.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.db.models import Max

from workflows.models import State, WorkflowInstance, WorkflowStepRun
from workflows.services.context import VARS_MAX_BYTES, compact_context_blob
from workflows.services.executors.factory import StepExecutorFactory

if TYPE_CHECKING:
    from workflows.services.types import ExecutorResult


_TERMINAL_STATES: set[str] = {
    State.REJECTED,
    State.FAILED,
    State.ABORTED,
    State.FINALIZED,
    State.STOP,
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


def _advance_pointer(inst: WorkflowInstance, target_step: str | None = None) -> bool:
    """Advance the step pointer.

    If target_step is provided, jump to that step (forward-only).
    Otherwise advance linearly to the next step.

    Returns:
        True if the pointer was advanced.
        False if there is no next step (only possible for linear advance).
    """
    if target_step is not None:
        steps = inst.get_steps()
        cur_idx = inst.get_current_step_index()

        try:
            tgt_idx = next(i for i, s in enumerate(steps) if str(s.get('id')) == target_step)
        except StopIteration:
            msg = f'Unknown goto target step id {target_step!r}'
            raise ValueError(msg)

        if tgt_idx <= cur_idx:
            msg = f'Backward or same-step goto is not allowed: {inst.current_step!r} -> {target_step!r}'
            raise ValueError(msg)

        inst.current_step = target_step
        inst.state = State.RUNNING
        inst.save(update_fields=['current_step', 'state'])
        return True

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


def _flatten_leaf_paths(src: dict[str, Any], *, prefix: str = '') -> list[tuple[str, Any]]:
    """Return a list of (dot_path, value) for all non-dict leaves in src.

    Dicts are traversed recursively. Empty dicts are treated as a leaf (assigned as {}).
    Lists are treated as leaves.
    """
    out: list[tuple[str, Any]] = []
    for k, v in src.items():
        key = str(k)
        path = f'{prefix}.{key}' if prefix else key
        if isinstance(v, dict):
            if not v:
                out.append((path, {}))
            else:
                out.extend(_flatten_leaf_paths(v, prefix=path))
        else:
            out.append((path, v))
    return out


def _apply_vars_assignments(dst: dict[str, Any], updates: dict[str, Any]) -> None:
    """Apply updates into dst as deterministic leaf assignments (overwrite allowed).

    Supported input forms:
    - dot-path assignments: {"user.name": "Alice"}
    - nested dict assignments: {"user": {"name": "Alice"}}

    Semantics:
    - Assignments overwrite existing values at the target leaf path.
    - Sibling keys are not deleted.
    - Empty dict values are treated as an explicit assignment (path is set to {}).
    """
    # Local import avoids widening the module import surface and keeps helpers consistent.
    from workflows.services.context import set_in

    for k, v in updates.items():
        key = str(k)

        # Dot-path form: assign directly.
        if '.' in key:
            set_in(dst, key, v, forbid_overwrite=False)
            continue

        # Nested dict form: traverse and assign leaves.
        if isinstance(v, dict):
            for path, leaf in _flatten_leaf_paths({key: v}):
                set_in(dst, path, leaf, forbid_overwrite=False)
            continue

        # Scalar at top-level key.
        dst[key] = v


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
    """Fail instance, persist engine error context, and append history row."""
    _fail_instance(inst)
    ctx = _make_engine_error_context(message=message, details=details)
    _persist_step_context(inst, ctx)

    # Best-effort history write (still inside same transaction).
    # step_type may be unknown here; use "Engine".
    _append_step_run(
        inst,
        step_id=str(inst.current_step),
        step_type='Engine',
        status=str(State.FAILED),
        context=dict(ctx),
        vars_delta=None,
        next_step=None,
    )

def _merge_global_vars(inst: WorkflowInstance, result: ExecutorResult) -> bool:
    """Merge vars into global $vars (overwrite allowed).

    Semantics:
    - Executors may return nested dicts and/or dot-path keys.
    - Updates are applied as leaf assignments into step_contexts["$vars"].
    - Overwrites are allowed.
    - Engine enforces VARS_MAX_BYTES and fails deterministically if exceeded.

    Returns:
        True if processing can continue.
        False if merge failed (illegal path) or vars exceed VARS_MAX_BYTES (instance marked FAILED).
    """
    if not (result.vars and isinstance(result.vars, dict)):
        return True

    step_contexts = dict(inst.step_contexts or {})
    vars_map_raw = step_contexts.get('$vars') or {}
    vars_map: dict[str, Any] = dict(vars_map_raw) if isinstance(vars_map_raw, dict) else {}

    try:
        _apply_vars_assignments(vars_map, dict(result.vars))
    except (ValueError, KeyError) as exc:
        _fail_instance_with_step_context(
            inst,
            message='Global vars merge failed.',
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


def _next_run_index(inst: WorkflowInstance) -> int:
    """Return the next monotonic run_index for this instance (1..n)."""
    agg = WorkflowStepRun.objects.filter(instance=inst).aggregate(m=Max('run_index'))
    cur = agg.get('m')
    return (int(cur) + 1) if cur is not None else 1


def _append_step_run(
    inst: WorkflowInstance,
    *,
    step_id: str,
    step_type: str,
    status: str,
    context: dict[str, Any] | None,
    vars_delta: dict[str, Any] | None,
    next_step: str | None,
) -> None:
    """Append an immutable execution record for the current attempt."""
    WorkflowStepRun.objects.create(
        instance=inst,
        run_index=_next_run_index(inst),
        step_id=step_id,
        step_type=step_type,
        status=str(status),
        context=context,
        vars_delta=vars_delta,
        next_step=next_step,
    )


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
                _fail_instance_with_step_context(
                    inst,
                    message='Executor raised an exception.',
                    details={'step_type': step_type, 'exception': str(exc)},
                )
                _recompute_parent(inst)
                break

            # Persist executor-produced context (snapshot/latest view)
            _persist_executor_context(inst, result)

            # Append immutable history row for this execution attempt
            history_context: dict[str, Any] | None = None
            if result.context is not None:
                history_context = result.context.to_dict()

            _append_step_run(
                inst,
                step_id=str(inst.current_step),
                step_type=step_type,
                status=str(result.status),
                context=history_context,
                vars_delta=(dict(result.vars) if isinstance(result.vars, dict) else None),
                next_step=(str(result.next_step) if result.next_step else None),
            )

            # Merge vars (overwrite allowed) and enforce VARS_MAX_BYTES.
            if not _merge_global_vars(inst, result):
                _recompute_parent(inst)
                break

            # Store resulting state.
            inst.state = result.status
            inst.save(update_fields=['state'])

            # Continuation semantics
            if result.status in _CONTINUE_STATES:
                try:
                    advanced = _advance_pointer(inst, result.next_step)
                except ValueError as exc:
                    _fail_instance_with_step_context(
                        inst,
                        message='Invalid goto target.',
                        details={'step_type': step_type, 'reason': str(exc)},
                    )
                    _recompute_parent(inst)
                    break

                if advanced:
                    signal = None
                    continue

                _recompute_parent(inst)
                break

            # Waiting or terminal semantics
            if result.status == State.AWAITING or result.status in _TERMINAL_STATES:
                _recompute_parent(inst)
                break

            # Defensive fallback
            _fail_instance_with_step_context(
                inst,
                message='Unknown executor status.',
                details={'status': str(result.status), 'step_type': step_type},
            )
            _recompute_parent(inst)
            break
