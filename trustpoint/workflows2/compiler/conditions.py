# workflows2/compiler/conditions.py
from __future__ import annotations

from typing import Any

from .errors import CompileError
from .templates import compile_template  # for ${...} used as values

COMPARE_OPERATORS: tuple[str, ...] = ('==', '!=', '<', '<=', '>', '>=')

CONDITION_OPERATORS: tuple[dict[str, Any], ...] = (
    {
        'key': 'exists',
        'title': 'exists',
        'description': 'True when the value is not null.',
        'shape': 'value',
        'scaffold': {'exists': '${vars.example}'},
    },
    {
        'key': 'not',
        'title': 'not',
        'description': 'Negates another condition.',
        'shape': 'condition',
        'scaffold': {'not': {'exists': '${vars.example}'}},
    },
    {
        'key': 'and',
        'title': 'and',
        'description': 'Logical AND over a non-empty list of conditions.',
        'shape': 'condition_list',
        'scaffold': {
            'and': [
                {'exists': '${vars.example}'},
                {
                    'compare': {
                        'left': '${vars.example}',
                        'op': '==',
                        'right': 1,
                    }
                },
            ]
        },
    },
    {
        'key': 'or',
        'title': 'or',
        'description': 'Logical OR over a non-empty list of conditions.',
        'shape': 'condition_list',
        'scaffold': {
            'or': [
                {
                    'compare': {
                        'left': '${vars.status}',
                        'op': '==',
                        'right': 200,
                    }
                },
                {
                    'compare': {
                        'left': '${vars.status}',
                        'op': '==',
                        'right': 201,
                    }
                },
            ]
        },
    },
    {
        'key': 'compare',
        'title': 'compare',
        'description': 'Compares two values using a comparison operator.',
        'shape': 'compare',
        'scaffold': {
            'compare': {
                'left': '${vars.example}',
                'op': '==',
                'right': 0,
            }
        },
    },
)


def compile_condition(cond: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(cond, dict) or len(cond) != 1:
        raise CompileError('Condition must be a mapping with exactly one operator', path=path)

    op, val = next(iter(cond.items()))

    if op == 'exists':
        v = _compile_value(val, path=f'{path}.exists')
        return {'op': 'exists', 'arg': v}

    if op == 'not':
        return {'op': 'not', 'arg': compile_condition(val, path=f'{path}.not')}

    if op in ('and', 'or'):
        if not isinstance(val, list) or not val:
            raise CompileError(f'"{op}" expects a non-empty list', path=path)
        return {'op': op, 'args': [compile_condition(c, path=f'{path}.{op}[{i}]') for i, c in enumerate(val)]}

    if op == 'compare':
        if not isinstance(val, dict):
            raise CompileError('"compare" expects a mapping', path=path)
        left = _compile_value(val.get('left'), path=f'{path}.compare.left')
        right = _compile_value(val.get('right'), path=f'{path}.compare.right')
        cmp_op = val.get('op')
        if cmp_op not in COMPARE_OPERATORS:
            raise CompileError('compare.op must be one of == != < <= > >=', path=f'{path}.compare.op')
        return {'op': 'compare', 'cmp': cmp_op, 'left': left, 'right': right}

    raise CompileError(f'Unknown condition operator "{op}"', path=path)


def _compile_value(v: Any, *, path: str) -> Any:
    # values can be scalars or ${...} refs inside a string
    if isinstance(v, (int, float, bool)) or v is None:
        return {'kind': 'lit', 'value': v}

    if isinstance(v, str):
        compiled = compile_template(v, path=path)
        if isinstance(compiled, dict) and compiled.get('kind') == 'template':
            # enforce single expr for condition values (keeps comparisons clean)
            parts = compiled['parts']
            if len(parts) == 1 and parts[0]['kind'] == 'expr':
                return parts[0]['expr']
            raise CompileError('Condition values must be a single ${...} expression or a literal', path=path)
        return {'kind': 'lit', 'value': v}

    raise CompileError('Unsupported value type in condition', path=path)