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
        rules = list(params.get('rules') or [])
        default = params.get('default')

        if not isinstance(default, dict):
            return ExecutorResult(
                status=State.FAILED,
                context=_logic_error('Logic step missing required "default" object.'),
            )

        ctx = _build_logic_context(instance)

        evaluations: list[bool] = []
        matched_rule_idx: int | None = None
        chosen_block: dict[str, Any] | None = None
        chosen_label: str = 'default'

        # Evaluate rules in order; first match wins
        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                evaluations.append(False)
                continue

            when_expr = rule.get('when')
            ok = _eval_when(when_expr, ctx)
            evaluations.append(ok)
            if ok:
                matched_rule_idx = idx
                chosen_block = rule
                chosen_label = f'rule[{idx}]'
                break

        if chosen_block is None:
            chosen_block = default

        actions = chosen_block.get('actions', [])
        then = chosen_block.get('then')

        # Apply actions (currently only "set") and compute vars updates
        try:
            flat_vars, assigned_keys = _execute_actions(actions=actions, ctx=ctx)
        except (ValueError, KeyError) as exc:
            return ExecutorResult(
                status=State.FAILED,
                context=_logic_error(f'Invalid actions: {exc}'),
            )

        outcome, next_step, stop_reason = _resolve_outcome(then)

        outputs: dict[str, Any] = {
            'logic': {
                'selected': chosen_label,
                'matched_rule': matched_rule_idx,
                'evaluations': evaluations,
                'assigned_keys': assigned_keys,
                'outcome': outcome,
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


def _eval_when(when: Any, ctx: dict[str, Any]) -> bool:
    """Evaluate `when`, allowing list-of-exprs as AND sugar."""
    if isinstance(when, list):
        # Empty lists should not happen (validator blocks), but be deterministic.
        if not when:
            return False
        for e in when:
            if not bool(_eval_value(e, ctx)):
                return False
        return True
    return bool(_eval_value(when, ctx))


def _eval_value(expr: Any, ctx: dict[str, Any]) -> Any:
    """Evaluate an expression deterministically.

    Supported forms:
    - primitives and lists are literal values
    - {"const": ...}
    - {"path": "ctx.vars.foo"} (or "vars.foo", "steps.step_1.outputs.x", etc.)
    - {"op": "...", ...} for supported operators
    """
    if expr is None:
        return None

    if isinstance(expr, (str, int, float, bool, list)):
        return expr

    if not isinstance(expr, dict):
        return None

    if 'const' in expr:
        return expr.get('const')

    if 'path' in expr and isinstance(expr.get('path'), str):
        return _resolve_path(ctx, str(expr['path']))

    op = str(expr.get('op') or '').strip().lower()
    if not op:
        return None

    if op in {'eq', 'ne', 'lt', 'lte', 'gt', 'gte'}:
        left = _eval_value(expr.get('left'), ctx)
        right = _eval_value(expr.get('right'), ctx)

        if op == 'eq':
            return left == right
        if op == 'ne':
            return left != right

        # Comparisons: TypeErrors become deterministic False
        try:
            if op == 'lt':
                return left < right
            if op == 'lte':
                return left <= right
            if op == 'gt':
                return left > right
            if op == 'gte':
                return left >= right
        except TypeError:
            return False

        return False

    if op == 'exists':
        # Exists means: path resolves to a non-None value
        arg = _eval_value(expr.get('arg'), ctx)
        return arg is not None

    if op == 'truthy':
        arg = _eval_value(expr.get('arg'), ctx)
        return bool(arg)

    if op == 'falsy':
        arg = _eval_value(expr.get('arg'), ctx)
        return not bool(arg)

    if op == 'not':
        return not bool(_eval_value(expr.get('arg'), ctx))

    if op == 'and':
        args = expr.get('args')
        if not isinstance(args, list) or not args:
            return False
        for a in args:
            if not bool(_eval_value(a, ctx)):
                return False
        return True

    if op == 'or':
        args = expr.get('args')
        if not isinstance(args, list) or not args:
            return False
        for a in args:
            if bool(_eval_value(a, ctx)):
                return True
        return False

    return None


def _resolve_path(ctx: dict[str, Any], path: str) -> Any:
    """Resolve a dot path against ctx.

    Accepted examples:
    - "ctx.vars.x"
    - "vars.x"
    - "steps.step_1.outputs.webhook.status"
    """
    if not isinstance(path, str) or not path:
        return None

    parts = [p for p in path.split('.') if p]
    if not parts:
        return None

    # Allow optional "ctx." prefix
    if parts[0] == 'ctx':
        parts = parts[1:]

    cur: Any = ctx
    for p in parts:
        if not isinstance(cur, dict):
            return None
        if p not in cur:
            return None
        cur = cur[p]
    return cur


def _execute_actions(*, actions: Any, ctx: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """Execute actions and return (flat_vars, assigned_keys).

    Supported actions (Pass-1):
    - {"type":"set", "assign": { "a.b": <expr>, ... } }
    """
    if actions is None:
        return None,_toggle_list([])

    if not isinstance(actions, list):
        raise ValueError('"actions" must be an array')

    nested_updates: dict[str, Any] = {}
    assigned: list[str] = []

    for i, act in enumerate(actions, start=1):
        if not isinstance(act, dict):
            raise ValueError(f'action #{i} must be an object')

        t = str(act.get('type') or '').strip().lower()
        if t != 'set':
            raise ValueError(f'action #{i} unknown type {t!r}')

        assign = act.get('assign')
        if not isinstance(assign, dict):
            raise ValueError(f'action #{i} set.assign must be an object')

        for raw_key, raw_val in assign.items():
            key = str(raw_key).strip()
            if not key:
                continue
            value = _eval_value(raw_val, ctx)
            # Validate + build nested structure; overwrite within this step is allowed.
            set_in(nested_updates, key, value, forbid_overwrite=False)
            assigned.append(key)

    flat = _flatten_to_dot_paths(nested_updates)
    return (flat or None), assigned


def _flatten_to_dot_paths(src: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict):
            if not node:
                # explicit assignment to empty dict
                out[prefix] = {}
                return
            for kk, vv in node.items():
                k2 = str(kk)
                p2 = f'{prefix}.{k2}' if prefix else k2
                walk(vv, p2)
        else:
            out[prefix] = node

    walk(src, '')
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

    # Deterministic fallback
    return 'pass', None, None


def _toggle_list(x: list[str]) -> list[str]:
    # small helper to keep tuple return type simple without extra branches
    return x
