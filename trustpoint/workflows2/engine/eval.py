"""Evaluate Workflow 2 expressions, templates, and conditions at runtime."""
from __future__ import annotations

import json
import re
from typing import Any

from .context import RuntimeContext
from .errors import ExecutionError


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
                raise ExecutionError('Invalid ref path')
            return _resolve_ref(path, ctx)

        if kind == 'call':
            name = expr_ir.get('name')
            args = expr_ir.get('args', [])
            if not isinstance(name, str) or not isinstance(args, list):
                raise ExecutionError('Invalid call expression')
            vals = [eval_expr(a, ctx) for a in args]
            return _call(name, vals)

    # allow literals directly (defensive)
    if isinstance(expr_ir, (str, int, float, bool)) or expr_ir is None:
        return expr_ir

    raise ExecutionError('Unsupported expression IR')


def render_template(value: Any, ctx: RuntimeContext) -> Any:
    """Render templates or nested template-bearing structures.

    - raw strings (returned as-is)
    - compiled template IR {"kind":"template","parts":[...]}
    - nested structures already processed by compiler (dict/list)
    """
    if isinstance(value, dict) and value.get('kind') == 'template':
        parts = value.get('parts', [])
        if not isinstance(parts, list):
            raise ExecutionError('Invalid template parts')
        out: list[str] = []
        for p in parts:
            if not isinstance(p, dict):
                raise ExecutionError('Invalid template part')
            if p.get('kind') == 'text':
                out.append(str(p.get('value', '')))
            elif p.get('kind') == 'expr':
                v = eval_expr(p.get('expr'), ctx)
                out.append('' if v is None else str(v))
            else:
                raise ExecutionError('Invalid template part kind')
        return ''.join(out)

    if isinstance(value, list):
        return [render_template(v, ctx) for v in value]

    if isinstance(value, dict):
        # template parts already handled above
        if 'kind' in value and value['kind'] in {'ref', 'lit', 'call'}:
            return eval_expr(value, ctx)
        return {k: render_template(v, ctx) for k, v in value.items()}

    return value


def eval_condition(cond_ir: Any, ctx: RuntimeContext) -> bool:
    """Very tolerant condition evaluator.

    Supported families (any mix):
      A) v2-ish:
         {"kind":"exists","expr":<expr_ir>}
         {"kind":"compare","left":<expr_ir>,"op":"==","right":<expr_ir|literal>}
         {"kind":"and","items":[...]} / {"kind":"or","items":[...]} / {"kind":"not","item":...}

      B) YAML-ish tolerated:
         {"exists": <expr_ir|ref>}  # or "expr" field
         {"compare": {"left":..., "op":..., "right":...}}
         {"and":[...]} / {"or":[...]} / {"not":...}

      C) classic op/args (common in rule engines):
         {"op":"and","args":[cond,...]}
         {"op":"or","args":[cond,...]}
         {"op":"not","arg":cond}
         {"op":"exists","arg":<expr_ir|ref>}
         {"op":"compare","left":..., "cmp":"==", "right":...}
         {"op":"eq"|"ne"|"lt"|"lte"|"gt"|"gte","left":..., "right":...}
         {"op":"=="| "!=" | "<" | "<=" | ">" | ">=","left":..., "right":...}
    """
    if not isinstance(cond_ir, dict):
        raise ExecutionError('Unsupported condition IR')

    # ---------- family C: op/args ----------
    if 'op' in cond_ir:
        op = cond_ir.get('op')

        # boolean ops
        if op == 'and':
            args = cond_ir.get('args')
            if not isinstance(args, list):
                raise ExecutionError('and expects args list')
            return all(eval_condition(a, ctx) for a in args)

        if op == 'or':
            args = cond_ir.get('args')
            if not isinstance(args, list):
                raise ExecutionError('or expects args list')
            return any(eval_condition(a, ctx) for a in args)

        if op == 'not':
            inner = cond_ir.get('arg')
            return not eval_condition(inner, ctx)

        # exists
        if op == 'exists':
            expr = cond_ir.get('arg') if 'arg' in cond_ir else cond_ir.get('expr')
            v = _eval_value(expr, ctx)
            return v is not None

        # compare variants
        if op == 'compare':
            left = cond_ir.get('left')
            cmpop = cond_ir.get('cmp', cond_ir.get('op2', cond_ir.get('operator')))
            right = cond_ir.get('right')
            lval = _eval_value(left, ctx)
            rval = _eval_value(right, ctx)
            return _compare(lval, cmpop, rval)

        # comparator as op itself
        if op in ('==', '!=', '<', '<=', '>', '>='):
            left = cond_ir.get('left')
            right = cond_ir.get('right')
            lval = _eval_value(left, ctx)
            rval = _eval_value(right, ctx)
            return _compare(lval, op, rval)

        # word comparators
        if op in ('eq', 'ne', 'lt', 'lte', 'gt', 'gte'):
            left = cond_ir.get('left')
            right = cond_ir.get('right')
            lval = _eval_value(left, ctx)
            rval = _eval_value(right, ctx)
            sym = {'eq': '==', 'ne': '!=', 'lt': '<', 'lte': '<=', 'gt': '>', 'gte': '>='}[op]
            return _compare(lval, sym, rval)

        raise ExecutionError('Unsupported condition op')

    # ---------- family A/B: kind/keys ----------
    kind = cond_ir.get('kind')

    # exists
    if kind == 'exists' or 'exists' in cond_ir:
        expr = cond_ir.get('expr', cond_ir.get('exists'))
        v = _eval_value(expr, ctx)
        return v is not None

    # compare
    if kind == 'compare' or 'compare' in cond_ir:
        c = cond_ir if kind == 'compare' else cond_ir.get('compare', {})
        if not isinstance(c, dict):
            raise ExecutionError('compare expects object')
        left = c.get('left')
        op = c.get('op')
        right = c.get('right')
        lval = _eval_value(left, ctx)
        rval = _eval_value(right, ctx)
        return _compare(lval, op, rval)

    # boolean ops
    if kind == 'and' or 'and' in cond_ir:
        items = cond_ir.get('items', cond_ir.get('and'))
        if not isinstance(items, list):
            raise ExecutionError('and expects list')
        return all(eval_condition(x, ctx) for x in items)

    if kind == 'or' or 'or' in cond_ir:
        items = cond_ir.get('items', cond_ir.get('or'))
        if not isinstance(items, list):
            raise ExecutionError('or expects list')
        return any(eval_condition(x, ctx) for x in items)

    if kind == 'not' or 'not' in cond_ir:
        inner = cond_ir.get('item', cond_ir.get('not'))
        return not eval_condition(inner, ctx)

    raise ExecutionError('Unsupported condition IR')


# ------------------------- helpers ------------------------- #


def _eval_value(v: Any, ctx: RuntimeContext) -> Any:
    """Evaluate a value that may contain expression or template IR.

    - expression IR {"kind":"ref"/"lit"/"call"}
    - template IR {"kind":"template"...}
    - plain literal
    """
    if isinstance(v, dict) and v.get('kind') in {'ref', 'lit', 'call'}:
        return eval_expr(v, ctx)
    return render_template(v, ctx)


def _resolve_ref(path: list[Any], ctx: RuntimeContext) -> Any:
    root = path[0]
    if root == 'event':
        cur: Any = ctx.event
    elif root == 'vars':
        cur = ctx.vars
    else:
        raise ExecutionError('Invalid ref root')

    for seg in path[1:]:
        if not isinstance(seg, str):
            raise ExecutionError('Invalid ref segment')
        if isinstance(cur, dict):
            cur = cur.get(seg)
        else:
            return None
    return cur


def _compare(lval: Any, op: Any, rval: Any) -> bool:
    if op not in ('==', '!=', '<', '<=', '>', '>='):
        raise ExecutionError(f'Unsupported compare op: {op}')

    lval, rval = _normalize_compare_values(lval, rval)

    try:
        if op == '==':
            return bool(lval == rval)
        if op == '!=':
            return bool(lval != rval)
        if op == '<':
            return bool(lval < rval)
        if op == '<=':
            return bool(lval <= rval)
        if op == '>':
            return bool(lval > rval)
        if op == '>=':
            return bool(lval >= rval)
    except TypeError:
        return False
    return False


_NUMERIC_STRING_RE = re.compile(r'^-?\d+(?:\.\d+)?$')


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
    # numeric
    if name == 'add':
        # add(a,b,c,...) -> sum
        return sum(_num(args, i) for i in range(len(args)))
    if name == 'mul':
        # mul(a,b,c,...) -> product
        out = 1.0
        for i in range(len(args)):
            out *= _num(args, i)
        return out
    if name == 'sub':
        # sub(a,b) only
        if len(args) != 2:
            msg = 'sub expects exactly 2 args'
            raise ExecutionError(msg)
        return _num(args, 0) - _num(args, 1)
    if name == 'div':
        # div(a,b) only
        if len(args) != 2:
            msg = 'div expects exactly 2 args'
            raise ExecutionError(msg)
        denom = _num(args, 1)
        return _num(args, 0) / denom if denom != 0 else None
    if name == 'min':
        if not args:
            msg = 'min expects at least 1 arg'
            raise ExecutionError(msg)
        return min(args)
    if name == 'max':
        if not args:
            msg = 'max expects at least 1 arg'
            raise ExecutionError(msg)
        return max(args)
    if name == 'round':
        if not args:
            msg = 'round expects at least 1 arg'
            raise ExecutionError(msg)
        x = _num(args, 0)
        nd = int(args[1]) if len(args) > 1 else 0
        return round(x, nd)
    if name == 'int':
        return int(args[0])
    if name == 'float':
        return float(args[0])

    # string
    if name == 'str':
        return '' if args[0] is None else str(args[0])
    if name == 'lower':
        return str(args[0]).lower()
    if name == 'upper':
        return str(args[0]).upper()
    if name == 'concat':
        return ''.join('' if a is None else str(a) for a in args)

    # serialization
    if name == 'json':
        return json.dumps(args[0], ensure_ascii=False, sort_keys=True)

    raise ExecutionError(f'Call not allowed: {name}')


def _num(args: list[Any], idx: int) -> float:
    if idx >= len(args):
        raise ExecutionError('Missing numeric argument')
    v = args[idx]
    if v is None:
        return 0.0
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(v)
    except Exception as e:
        raise ExecutionError('Argument is not numeric') from e
