"""Compile `${...}` templates into template IR fragments."""
from __future__ import annotations

import re
from typing import Any

from .errors import CompileError
from .expr import CallExpr, RefExpr, parse_expr

EXPR_PATTERN = re.compile(r'\$\{([^}]+)\}')


def compile_template(value: Any, *, path: str) -> Any:
    """Compile a string containing `${...}` into template IR.

      {"kind":"template","parts":[{"kind":"text","value":...},{"kind":"expr","expr":...},...]}

    If `value` is not a string or contains no `${...}`, return as-is.
    """
    if not isinstance(value, str):
        return value

    matches = list(EXPR_PATTERN.finditer(value))
    if not matches:
        return value

    parts: list[dict[str, Any]] = []
    last = 0

    for m in matches:
        if m.start() > last:
            parts.append({'kind': 'text', 'value': value[last:m.start()]})

        inner = m.group(1)
        expr_ast = parse_expr(inner, path=path)
        parts.append({'kind': 'expr', 'expr': _expr_to_ir(expr_ast)})

        last = m.end()

    if last < len(value):
        parts.append({'kind': 'text', 'value': value[last:]})

    return {'kind': 'template', 'parts': parts}


def compile_templates_deep(obj: Any, *, path: str) -> Any:
    """Recursively compile `${...}` templates in nested structures.

      - strings
      - lists
      - dicts (string keys only)

    Useful for webhook bodies, headers, and any JSON-like structures.
    """
    if isinstance(obj, str):
        return compile_template(obj, path=path)

    if isinstance(obj, list):
        return [compile_templates_deep(v, path=f'{path}[{i}]') for i, v in enumerate(obj)]

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                msg = 'Only string keys are supported in mappings.'
                raise CompileError(msg, path=path)
            out[k] = compile_templates_deep(v, path=f'{path}.{k}')
        return out

    return obj


def _expr_to_ir(expr_ast: Any) -> Any:
    """Convert parsed expression AST nodes into serializable IR."""
    if isinstance(expr_ast, RefExpr):
        return {'kind': 'ref', 'path': expr_ast.path}

    if isinstance(expr_ast, CallExpr):
        return {'kind': 'call', 'name': expr_ast.name, 'args': [_expr_to_ir(a) for a in expr_ast.args]}

    if isinstance(expr_ast, (str, int, float, bool)) or expr_ast is None:
        return {'kind': 'lit', 'value': expr_ast}

    msg = 'Unsupported expression AST node'
    raise CompileError(msg)
