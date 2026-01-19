"""Logic step executor.

Declarative, deterministic logic evaluation.

Reads:
- ctx.* (read-only runtime context)
- ctx.vars.*
- prior step contexts via ctx.steps.<safe_step_id>.* (full stored contexts)

Writes:
- returns ExecutorResult.vars as dot-path assignments to be merged into $vars (overwrite allowed)

Outcomes:
- pass: continue linearly
- goto(step_id): forward-only jump (engine enforces)
- stop: terminal State.STOP (not auto-finalized)
"""

from __future__ import annotations

from typing import Any

from workflows.models import State, WorkflowInstance
from workflows.services.context import build_context, set_in
from workflows.services.executors.factory import AbstractStepExecutor
from workflows.services.types import ExecutorResult, StepContext


class LogicExecutor(AbstractStepExecutor):
    """Execute a declarative Logic step."""

    def do_execute(self, instance: WorkflowInstance, _signal: str | None) -> ExecutorResult:
        step = next((s for s in instance.get_steps() if s.get('id') == instance.current_step), None)
        if step is None:
            msg = f'Unknown current step id {instance.current_step!r}'
            raise ValueError(msg)

        params: dict[str, Any] = dict(step.get('params') or {})
        cases = list(params.get('cases') or [])
        default = params.get('default')

        if default is None:
            return ExecutorResult(
                status=State.FAILED,
                context=_logic_error('Logic step missing required "default" outcome.'),
            )

        ctx = _build_logic_context(instance)

        evaluations: list[bool] = []
        matched_idx: int | None = None
        chosen_case: dict[str, Any] | None = None

        for idx, case in enumerate(cases):
            if not isinstance(case, dict):
                evaluations.append(False)
                continue

            when_expr = case.get('when')
            ok = bool(_eval_bool_expr(when_expr, ctx))
            evaluations.append(ok)
            if ok and matched_idx is None:
                matched_idx = idx
                chosen_case = case
                break

        if matched_idx is not None and chosen_case is not None:
            set_map = chosen_case.get('set')
            then = chosen_case.get('then')
        else:
            set_map = None
            then = default

        flat_vars: dict[str, Any] | None = None
        try:
            flat_vars = _build_vars_assignments(set_map)
        except (ValueError, KeyError) as exc:
            return ExecutorResult(
                status=State.FAILED,
                context=_logic_error(f'Invalid vars assignment: {exc}'),
            )

        outcome, next_step, stop_reason = _resolve_outcome(then)

        outputs: dict[str, Any] = {
            'logic': {
                'outcome': outcome,
                'matched_case': matched_idx,
                'evaluations': evaluations,
                'goto': next_step,
                'stop_reason': stop_reason,
            }
        }

        step_ctx = StepContext(
            step_type='Logic',
            step_status=outcome,
            error=None,
            outputs=outputs,
        )

        if outcome == 'stop':
            return ExecutorResult(status=State.STOP, context=step_ctx, vars=flat_vars)

        if outcome == 'goto':
            return ExecutorResult(status=State.PASSED, context=step_ctx, vars=flat_vars, next_step=next_step)

        return ExecutorResult(status=State.PASSED, context=step_ctx, vars=flat_vars)


def _logic_error(message: str) -> StepContext:
    return StepContext(
        step_type='Logic',
        step_status='failed',
        error=message,
        outputs={'logic': {'outcome': 'failed'}},
    )


def _build_logic_context(instance: WorkflowInstance) -> dict[str, Any]:
    """Build ctx for Logic evaluation.

    Uses build_context() for meta/workflow/device/request/vars and replaces ctx.steps
    with full stored step contexts mapped by safe step ids.
    """
    ctx = build_context(instance)
    ctx['steps'] = _build_full_steps_context(instance)
    return ctx


def _safe_step_key(raw_id: str) -> str:
    if not raw_id:
        return 'step'
    safe = ''.join(ch if (ch.isalnum() or ch == '_') else '_' for ch in raw_id)
    if not (safe[0].isalpha() or safe[0] == '_'):
        safe = f's_{safe}'
    return safe


def _build_full_steps_context(instance: WorkflowInstance) -> dict[str, Any]:
    out: dict[str, Any] = {}
    sc = instance.step_contexts or {}
    if not isinstance(sc, dict):
        return out

    for raw_step_id, blob in sc.items():
        if not isinstance(raw_step_id, str):
            continue
        if raw_step_id.startswith('$'):
            continue
        if not isinstance(blob, dict):
            continue
        out[_safe_step_key(raw_step_id)] = blob
    return out


def _eval_bool_expr(expr: Any, ctx: dict[str, Any]) -> bool:
    """Evaluate an expression and coerce to boolean deterministically."""
    v = _eval_value(expr, ctx)
    return bool(v)


def _eval_value(expr: Any, ctx: dict[str, Any]) -> Any:
    if expr is None:
        return None

    # literal primitives and arrays are allowed as literals
    if isinstance(expr, (str, int, float, bool, list)):
        return expr

    if not isinstance(expr, dict):
        return None

    # Path lookup
    if 'path' in expr and isinstance(expr.get('path'), str):
        return _resolve_path(ctx, str(expr['path']))

    op = str(expr.get('op') or '').strip().lower()
    if not op:
        return None

    if op == 'eq':
        left = _eval_value(expr.get('left'), ctx)
        right = _eval_value(expr.get('right'), ctx)
        return left == right

    if op == 'exists':
        arg = _eval_value(expr.get('arg'), ctx)
        return arg is not None

    if op == 'truthy':
        arg = _eval_value(expr.get('arg'), ctx)
        return bool(arg)

    if op == 'falsy':
        arg = _eval_value(expr.get('arg'), ctx)
        return not bool(arg)

    if op == 'not':
        return not _eval_bool_expr(expr.get('arg'), ctx)

    if op == 'and':
        args = expr.get('args')
        if not isinstance(args, list) or not args:
            return False
        for a in args:
            if not _eval_bool_expr(a, ctx):
                return False
        return True

    if op == 'or':
        args = expr.get('args')
        if not isinstance(args, list) or not args:
            return False
        for a in args:
            if _eval_bool_expr(a, ctx):
                return True
        return False

    return None


def _resolve_path(ctx: dict[str, Any], path: str) -> Any:
    """Resolve a dot path like 'ctx.vars.x' against {'ctx': ctx}."""
    if not isinstance(path, str) or not path:
        return None

    parts = [p for p in path.split('.') if p]
    if not parts:
        return None

    # We support paths that start with "ctx".
    root: Any = ctx
    if parts[0] == 'ctx':
        root = ctx
        parts = parts[1:]

    cur: Any = root
    for p in parts:
        if not isinstance(cur, dict):
            return None
        if p not in cur:
            return None
        cur = cur[p]
    return cur


def _build_vars_assignments(set_map: Any) -> dict[str, Any] | None:
    """Convert a case 'set' mapping into dot-path assignments."""
    if set_map is None:
        return None
    if not isinstance(set_map, dict):
        raise ValueError('"set" must be a dict of dot-path assignments')

    out: dict[str, Any] = {}
    for k, v in set_map.items():
        key = str(k).strip()
        if not key:
            continue
        # Use set_in to enforce segment rules and to build a nested structure.
        # We return dot-path keys anyway, but this validates the path.
        set_in(out, key, v, forbid_overwrite=False)
    # Flatten nested dict back into dot paths, so the engine can apply leaf-assignments.
    return _flatten_to_dot_paths(out)


def _flatten_to_dot_paths(src: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict):
            if not node:
                out[prefix] = {}
                return
            for kk, vv in node.items():
                k2 = str(kk)
                p2 = f'{prefix}.{k2}' if prefix else k2
                walk(vv, p2)
        else:
            out[prefix] = node

    walk(src, '')
    # Remove empty key that could appear if src is empty.
    out.pop('', None)
    return out


def _resolve_outcome(then: Any) -> tuple[str, str | None, str | None]:
    """Return (outcome, goto_step, stop_reason)."""
    # Missing "then" means pass (human-friendly); default is required at step level.
    if then is None:
        return 'pass', None, None

    if isinstance(then, dict):
        if then.get('pass') is True:
            return 'pass', None, None

        if 'goto' in then:
            tgt = str(then.get('goto') or '').strip()
            if not tgt:
                return 'pass', None, None
            return 'goto', tgt, None

        if 'stop' in then:
            stop_cfg = then.get('stop')
            reason: str | None = None
            if isinstance(stop_cfg, dict):
                r = stop_cfg.get('reason')
                if r is not None:
                    reason = str(r)
            return 'stop', None, reason

    # Fallback: treat unknown outcome as pass (deterministic).
    return 'pass', None, None
