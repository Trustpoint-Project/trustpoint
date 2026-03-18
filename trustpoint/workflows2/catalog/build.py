# workflows2/catalog/build.py
from __future__ import annotations

from typing import Any

from workflows2.catalog.presets import PRESETS
from workflows2.catalog.steps import COMMON_STEP_FIELDS, step_specs
from workflows2.compiler.compiler import COMPUTE_OPERATORS
from workflows2.compiler.conditions import COMPARE_OPERATORS, CONDITION_OPERATORS
from workflows2.compiler.expr import ALLOWED_REF_ROOTS, EXPRESSION_FUNCTION_GROUPS
from workflows2.events.registry import get_event_registry


def _sorted_or_none(value: Any) -> list[str] | None:
    if value is None:
        return None
    return sorted(str(x) for x in value)


def build_context_catalog() -> dict[str, Any]:
    reg = get_event_registry()

    events: list[dict[str, Any]] = []
    for spec in reg.all_specs():
        events.append(
            {
                'key': spec.key,
                'title': getattr(spec, 'title', '') or spec.key,
                'group': spec.key.split('.', 1)[0] if '.' in spec.key else spec.key,
                'description': spec.description,
                'allowed_step_types': (
                    sorted(list(spec.allowed_step_types))
                    if spec.allowed_step_types is not None
                    else None
                ),
                'context_vars': [
                    {
                        'path': v.path,
                        'title': getattr(v, 'title', '') or v.path,
                        'type': v.type,
                        'description': v.description,
                        'example': v.example,
                    }
                    for v in (spec.context_vars or [])
                ],
            }
        )

    steps: list[dict[str, Any]] = []
    for s in step_specs():
        steps.append(
            {
                'type': s.type,
                'title': s.title,
                'description': s.description,
                'category': s.category,
                'fields': [
                    {
                        'key': f.key,
                        'title': f.title,
                        'description': f.description,
                        'required': bool(f.required),
                        'field_kind': f.field_kind,
                        'default': f.default,
                        'scaffold': f.scaffold,
                        'enum': list(f.enum) if f.enum is not None else None,
                        'group': f.group,
                    }
                    for f in s.fields
                ],
                'scaffold': {
                    'type': s.type,
                    **{
                        f.key: (f.scaffold if f.scaffold is not None else f.default)
                        for f in s.fields
                        if f.required
                    },
                },
            }
        )

    presets: list[dict[str, Any]] = []
    for p in PRESETS:
        presets.append(
            {
                'id': p.id,
                'title': p.title,
                'description': p.description,
                'areas': sorted(list(getattr(p, 'areas', set()))),
                'triggers': _sorted_or_none(getattr(p, 'triggers', None)),
                'step_types': _sorted_or_none(getattr(p, 'step_types', None)),
            }
        )

    return {
        'events': sorted(events, key=lambda x: x['key']),
        'steps': steps,
        'presets': presets,
        'dsl': {
            'conditions': {
                'operators': list(CONDITION_OPERATORS),
                'compare_operators': list(COMPARE_OPERATORS),
            },
            'expressions': {
                'ref_roots': list(ALLOWED_REF_ROOTS),
                'function_groups': [
                    {
                        'group': group['group'],
                        'functions': list(group['functions']),
                    }
                    for group in EXPRESSION_FUNCTION_GROUPS
                ],
            },
            'compute': {
                'operators': list(COMPUTE_OPERATORS),
            },
        },
        'meta': {
            'version': 4,
            'common_step_fields': [
                {
                    'key': f.key,
                    'title': f.title,
                    'description': f.description,
                    'required': bool(f.required),
                    'field_kind': f.field_kind,
                    'default': f.default,
                    'scaffold': f.scaffold,
                    'enum': list(f.enum) if f.enum is not None else None,
                    'group': f.group,
                }
                for f in COMMON_STEP_FIELDS
            ],
            'end_targets': ['$end', '$reject'],
        },
    }