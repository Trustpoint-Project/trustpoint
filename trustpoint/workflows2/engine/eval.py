"""Evaluate Workflow 2 expressions, templates, and conditions at runtime."""
from __future__ import annotations

import json
import operator
import re
from typing import TYPE_CHECKING, Any

from .errors import ExecutionError

if TYPE_CHECKING:
    from collections.abc import Callable

    from .context import RuntimeContext

BINARY_ARG_COUNT = 2

_COMPARE_FUNCS: dict[str, Callable[[Any, Any], Any]] = {
    '==': operator.eq,
    '!=': operator.ne,
    '<': operator.lt,
    '<=': operator.le,
    '>': operator.gt,
    '>=': operator.ge,
}

_NUMERIC_STRING_RE = re.compile(r'^-?\d+(?:\.\d+)?$')


def eval_expr(expr_ir: Any, ctx: RuntimeContext) -> Any:
    """Evaluate expression IR produced by the compiler.

    - {"kind":"ref","path":[...]}
    - {"kind":"lit","value":...}
    - {"kind":"call","name":..., "args":[...]}
    """
    if isinstance(expr_ir, dict):
        kind = expr_ir.get('kind')
        if kind == 'lit':
            return expr_ir.get('value')

        if kind == 'ref':
            path = expr_ir.get('path')
            if not isinstance(path, list) or not path:
                msg = 'Invalid ref path'
                raise ExecutionError(msg)
            return _resolve_ref(path, ctx)

        if kind == 'call':
            name = expr_ir.get('name')
            args = expr_ir.get('args', [])
            if not isinstance(name, str) or not isinstance(args, list):
                msg = 'Invalid call expression'
                raise ExecutionError(msg)
            values = [eval_expr(arg, ctx) for arg in args]
            return _call(name, values)

    if isinstance(expr_ir, (str, int, float, bool)) or expr_ir is None:
        return expr_ir

    msg = 'Unsupported expression IR'
    raise ExecutionError(msg)


def render_template(value: Any, ctx: RuntimeContext) -> Any:
    """Render templates or nested template-bearing structures."""
    if isinstance(value, dict) and value.get('kind') == 'template':
        parts = value.get('parts', [])
        if not isinstance(parts, list):
            msg = 'Invalid template parts'
            raise ExecutionError(msg)

        out: list[str] = []
        for part in parts:
            if not isinstance(part, dict):
                msg = 'Invalid template part'
                raise ExecutionError(msg)

            part_kind = part.get('kind')
            if part_kind == 'text':
                out.append(str(part.get('value', '')))
            elif part_kind == 'expr':
                rendered = eval_expr(part.get('expr'), ctx)
                out.append('' if rendered is None else str(rendered))
            else:
                msg = 'Invalid template part kind'
                raise ExecutionError(msg)

        return ''.join(out)

    if isinstance(value, list):
        return [render_template(item, ctx) for item in value]

    if isinstance(value, dict):
        if value.get('kind') in {'ref', 'lit', 'call'}:
            return eval_expr(value, ctx)
        return {key: render_template(item, ctx) for key, item in value.items()}

    return value


def eval_condition(cond_ir: Any, ctx: RuntimeContext) -> bool:
    """Evaluate condition IR.

    Supports:
      - compiled form from conditions.py:
        {"op":"exists","arg":...}
        {"op":"not","arg":...}
        {"op":"and"|"or","args":[...]}
        {"op":"compare","cmp":"==","left":...,"right":...}

      - compatibility form still used in tests:
        {"kind":"compare","left":...,"op":"==","right":...}
    """
    if not isinstance(cond_ir, dict):
        msg = 'Unsupported condition IR'
        raise ExecutionError(msg)

    kind = cond_ir.get('kind')
    if kind == 'compare':
        return _eval_compare(
            cond_ir.get('left'),
            cond_ir.get('op'),
            cond_ir.get('right'),
            ctx,
        )

    op = cond_ir.get('op')
    if op in {'and', 'or'}:
        return _eval_condition_group(op, cond_ir.get('args'), ctx)

    if op == 'not':
        return not eval_condition(cond_ir.get('arg'), ctx)

    if op == 'exists':
        return _eval_value(cond_ir.get('arg'), ctx) is not None

    if op == 'compare':
        return _eval_compare(
            cond_ir.get('left'),
            cond_ir.get('cmp'),
            cond_ir.get('right'),
            ctx,
        )

    msg = 'Unsupported condition op'
    raise ExecutionError(msg)


def _eval_condition_group(op: Any, items: Any, ctx: RuntimeContext) -> bool:
    if not isinstance(items, list):
        msg = f'{op} expects args list'
        raise ExecutionError(msg)

    if op == 'and':
        return all(eval_condition(item, ctx) for item in items)
    return any(eval_condition(item, ctx) for item in items)


def _eval_compare(left: Any, op: Any, right: Any, ctx: RuntimeContext) -> bool:
    lval = _eval_value(left, ctx)
    rval = _eval_value(right, ctx)
    return _compare(lval, op, rval)


def _eval_value(value: Any, ctx: RuntimeContext) -> Any:
    """Evaluate a value that may contain expression or template IR."""
    if isinstance(value, dict) and value.get('kind') in {'ref', 'lit', 'call'}:
        return eval_expr(value, ctx)
    return render_template(value, ctx)


def _resolve_ref(path: list[Any], ctx: RuntimeContext) -> Any:
    root = path[0]
    if root == 'event':
        current: Any = ctx.event
    elif root == 'vars':
        current = ctx.vars
    else:
        msg = 'Invalid ref root'
        raise ExecutionError(msg)

    for segment in path[1:]:
        if not isinstance(segment, str):
            msg = 'Invalid ref segment'
            raise ExecutionError(msg)
        if isinstance(current, dict):
            current = current.get(segment)
        else:
            return None

    return current


def _compare(lval: Any, op: Any, rval: Any) -> bool:
    if op not in _COMPARE_FUNCS:
        msg = f'Unsupported compare op: {op}'
        raise ExecutionError(msg)

    lval, rval = _normalize_compare_values(lval, rval)
    compare_func = _COMPARE_FUNCS[str(op)]

    try:
        return bool(compare_func(lval, rval))
    except TypeError:
        return False


def _normalize_compare_values(lval: Any, rval: Any) -> tuple[Any, Any]:
    if _is_numeric_value(lval) and isinstance(rval, str):
        coerced = _parse_numeric_string(rval)
        if coerced is not None:
            return lval, coerced

    if _is_numeric_value(rval) and isinstance(lval, str):
        coerced = _parse_numeric_string(lval)
        if coerced is not None:
            return coerced, rval

    return lval, rval


def _is_numeric_value(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _parse_numeric_string(value: str) -> int | float | None:
    text = value.strip()
    if not text or not _NUMERIC_STRING_RE.fullmatch(text):
        return None

    try:
        if '.' in text:
            return float(text)
        return int(text)
    except ValueError:
        return None


def _call(name: str, args: list[Any]) -> Any:
    handler = _CALL_HANDLERS.get(name)
    if handler is None:
        msg = f'Call not allowed: {name}'
        raise ExecutionError(msg)
    return handler(args)


def _call_add(args: list[Any]) -> Any:
    return sum(_num(args, index) for index in range(len(args)))


def _call_mul(args: list[Any]) -> Any:
    out = 1.0
    for index in range(len(args)):
        out *= _num(args, index)
    return out


def _call_sub(args: list[Any]) -> Any:
    return _call_binary_numeric('sub', args, lambda left, right: left - right)


def _call_div(args: list[Any]) -> Any:
    return _call_binary_numeric('div', args, _safe_divide)


def _call_min(args: list[Any]) -> Any:
    if not args:
        msg = 'min expects at least 1 arg'
        raise ExecutionError(msg)
    return min(args)


def _call_max(args: list[Any]) -> Any:
    if not args:
        msg = 'max expects at least 1 arg'
        raise ExecutionError(msg)
    return max(args)


def _call_round(args: list[Any]) -> Any:
    if not args:
        msg = 'round expects at least 1 arg'
        raise ExecutionError(msg)
    value = _num(args, 0)
    digits = int(args[1]) if len(args) > 1 else 0
    return round(value, digits)


def _call_int(args: list[Any]) -> Any:
    return int(args[0])


def _call_float(args: list[Any]) -> Any:
    return float(args[0])


def _call_str(args: list[Any]) -> Any:
    return '' if args[0] is None else str(args[0])


def _call_lower(args: list[Any]) -> Any:
    return str(args[0]).lower()


def _call_upper(args: list[Any]) -> Any:
    return str(args[0]).upper()


def _call_concat(args: list[Any]) -> Any:
    return ''.join('' if arg is None else str(arg) for arg in args)


def _call_json(args: list[Any]) -> Any:
    return json.dumps(args[0], ensure_ascii=False, sort_keys=True)


def _call_binary_numeric(
    name: str,
    args: list[Any],
    func: Callable[[float, float], Any],
) -> Any:
    if len(args) != BINARY_ARG_COUNT:
        msg = f'{name} expects exactly 2 args'
        raise ExecutionError(msg)

    left = _num(args, 0)
    right = _num(args, 1)
    return func(left, right)


def _safe_divide(left: float, right: float) -> float | None:
    if right == 0:
        return None
    return left / right


_CALL_HANDLERS: dict[str, Callable[[list[Any]], Any]] = {
    'add': _call_add,
    'mul': _call_mul,
    'sub': _call_sub,
    'div': _call_div,
    'min': _call_min,
    'max': _call_max,
    'round': _call_round,
    'int': _call_int,
    'float': _call_float,
    'str': _call_str,
    'lower': _call_lower,
    'upper': _call_upper,
    'concat': _call_concat,
    'json': _call_json,
}


def _num(args: list[Any], idx: int) -> float:
    if idx >= len(args):
        msg = 'Missing numeric argument'
        raise ExecutionError(msg)

    value = args[idx]
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)

    try:
        return float(value)
    except Exception as exc:
        msg = 'Argument is not numeric'
        raise ExecutionError(msg) from exc
