"""Validation for Logic step params."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error, is_bare_var_path

_ALLOWED_OPS: set[str] = {
    'eq',
    'ne',
    'lt',
    'lte',
    'gt',
    'gte',
    'and',
    'or',
    'not',
    'exists',
    'truthy',
    'falsy',
}


def validate_logic_step(
    *,
    idx: int,
    step_id: str,
    params: dict[str, Any],
    errors: list[str],
    steps: list[Any],
) -> None:
    """Validate Logic step parameters (Pass-1).

    Supports:
    - rules: list of rule objects
    - default: object (required)
    - rule.when: either an expr object/primitive OR a non-empty list of exprs (AND sugar)
    - actions: list (supports set.assign only)
    - then: pass/goto/stop (exactly one)
    - goto must be forward-only and refer to an existing step id
    """
    default = params.get('default')
    if not isinstance(default, dict):
        error(errors, _('Step #%s (Logic): default is required and must be an object.') % idx)

    rules = params.get('rules', [])
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        error(errors, _('Step #%s (Logic): rules must be an array if provided.') % idx)
        return

    step_ids: set[str] = {
        str(s.get('id'))
        for s in steps
        if isinstance(s, dict) and isinstance(s.get('id'), str) and str(s.get('id')).strip()
    }
    index_map: dict[str, int] = {}
    for i, s in enumerate(steps):
        if isinstance(s, dict) and isinstance(s.get('id'), str):
            sid = str(s.get('id'))
            if sid.strip():
                index_map[sid] = i

    # Validate rules
    for j, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            error(errors, _('Step #%s (Logic): rule #%s must be an object.') % (idx, j))
            continue

        when = rule.get('when')
        if when is None:
            error(errors, _('Step #%s (Logic): rule #%s is missing "when".') % (idx, j))
        else:
            _validate_when(idx=idx, label=f'rule #{j} when', when=when, errors=errors)

        actions = rule.get('actions', [])
        _validate_actions(idx=idx, label=f'rule #{j}', actions=actions, errors=errors)

        then = rule.get('then')
        _validate_then(
            idx=idx,
            label=f'rule #{j}',
            then=then,
            errors=errors,
            step_id=step_id,
            step_ids=step_ids,
            index_map=index_map,
        )

    # Validate default
    if isinstance(default, dict):
        actions = default.get('actions', [])
        _validate_actions(idx=idx, label='default', actions=actions, errors=errors)

        then = default.get('then')
        _validate_then(
            idx=idx,
            label='default',
            then=then,
            errors=errors,
            step_id=step_id,
            step_ids=step_ids,
            index_map=index_map,
        )


def _validate_when(*, idx: int, label: str, when: Any, errors: list[str]) -> None:
    """Validate `when` which may be an expr or a list-of-exprs (AND sugar)."""
    if isinstance(when, list):
        if not when:
            error(errors, _('Step #%s (Logic): %s must not be an empty array.') % (idx, label))
            return
        for i, e in enumerate(when, start=1):
            _validate_expr(idx=idx, label=f'{label}[{i}]', expr=e, errors=errors)
        return

    _validate_expr(idx=idx, label=label, expr=when, errors=errors)


def _validate_actions(*, idx: int, label: str, actions: Any, errors: list[str]) -> None:
    if actions is None:
        return
    if not isinstance(actions, list):
        error(errors, _('Step #%s (Logic): %s actions must be an array.') % (idx, label))
        return

    for k, act in enumerate(actions, start=1):
        if not isinstance(act, dict):
            error(errors, _('Step #%s (Logic): %s action #%s must be an object.') % (idx, label, k))
            continue

        t = str(act.get('type') or '').strip().lower()
        if t != 'set':
            error(errors, _('Step #%s (Logic): %s action #%s has unknown type "%s".') % (idx, label, k, t))
            continue

        assign = act.get('assign')
        if not isinstance(assign, dict):
            error(errors, _('Step #%s (Logic): %s action #%s set.assign must be an object.') % (idx, label, k))
            continue

        for raw_key, raw_val in assign.items():
            key = str(raw_key).strip()
            if not key or not is_bare_var_path(key):
                error(
                    errors,
                    _(
                        "Step #%s (Logic): %s action #%s set.assign key '%s' must be a variable path "
                        "like 'serial_number' or 'http.status' (no 'vars.' prefix)."
                    )
                    % (idx, label, k, key),
                )
                continue
            _validate_expr(idx=idx, label=f'{label} action #{k} assign {key}', expr=raw_val, errors=errors)


def _validate_then(
    *,
    idx: int,
    label: str,
    then: Any,
    errors: list[str],
    step_id: str,
    step_ids: set[str],
    index_map: dict[str, int],
) -> None:
    if not isinstance(then, dict):
        error(errors, _('Step #%s (Logic): %s then is required and must be an object.') % (idx, label))
        return

    # Exactly one of: pass/goto/stop
    keys_present = 0
    if then.get('pass') is True:
        keys_present += 1
    if 'goto' in then:
        keys_present += 1
    if 'stop' in then:
        keys_present += 1

    if keys_present != 1:
        error(errors, _('Step #%s (Logic): %s then must specify exactly one of pass/goto/stop.') % (idx, label))
        return

    # pass
    if then.get('pass') is True:
        return

    # goto
    if 'goto' in then:
        tgt = str(then.get('goto') or '').strip()
        if not tgt:
            error(errors, _('Step #%s (Logic): %s goto must be a non-empty step id.') % (idx, label))
            return
        if tgt not in step_ids:
            error(errors, _("Step #%s (Logic): %s goto target '%s' does not match any step id.") % (idx, label, tgt))
            return

        cur_idx = index_map.get(step_id)
        tgt_idx = index_map.get(tgt)
        if cur_idx is None or tgt_idx is None:
            return
        if tgt_idx <= cur_idx:
            error(
                errors,
                _(
                    "Step #%s (Logic): %s goto target '%s' must refer to a later step (forward-only)."
                )
                % (idx, label, tgt),
            )
        return

    # stop
    stop_cfg = then.get('stop')
    if stop_cfg is True:
        return
    if isinstance(stop_cfg, dict):
        r = stop_cfg.get('reason')
        if r is not None and not isinstance(r, str):
            error(errors, _('Step #%s (Logic): %s stop.reason must be a string if provided.') % (idx, label))
        return

    error(errors, _('Step #%s (Logic): %s stop must be true or an object.') % (idx, label))


def _validate_expr(*, idx: int, label: str, expr: Any, errors: list[str]) -> None:
    """Validate expression shape only (Pass-1).

    Note:
        This does NOT evaluate. It validates that the expression tree is well-formed.
    """
    if expr is None:
        return

    if isinstance(expr, (str, int, float, bool, list)):
        return

    if not isinstance(expr, dict):
        error(errors, _('Step #%s (Logic): %s expression must be an object or primitive.') % (idx, label))
        return

    if 'path' in expr:
        p = expr.get('path')
        if not isinstance(p, str) or not p.strip():
            error(errors, _('Step #%s (Logic): %s path must be a non-empty string.') % (idx, label))
        return

    if 'const' in expr:
        return

    op = str(expr.get('op') or '').strip().lower()
    if op not in _ALLOWED_OPS:
        error(errors, _('Step #%s (Logic): %s has unknown op "%s".') % (idx, label, op))
        return

    if op in {'and', 'or'}:
        args = expr.get('args')
        if not isinstance(args, list) or not args:
            error(errors, _('Step #%s (Logic): %s %s requires a non-empty args array.') % (idx, label, op))
            return
        for i, a in enumerate(args, start=1):
            _validate_expr(idx=idx, label=f'{label}.{op}[{i}]', expr=a, errors=errors)
        return

    if op in {'not', 'exists', 'truthy', 'falsy'}:
        _validate_expr(idx=idx, label=f'{label}.{op}', expr=expr.get('arg'), errors=errors)
        return

    # binary ops
    _validate_expr(idx=idx, label=f'{label}.{op}.left', expr=expr.get('left'), errors=errors)
    _validate_expr(idx=idx, label=f'{label}.{op}.right', expr=expr.get('right'), errors=errors)
