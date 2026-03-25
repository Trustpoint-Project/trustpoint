"""Build the editor context catalog for the Workflow 2 frontend."""

from __future__ import annotations

from typing import Any

from workflows2.catalog.presets import PRESETS
from workflows2.catalog.steps import COMMON_STEP_FIELDS, step_specs
from workflows2.catalog.trigger_sources import build_trigger_source_catalog
from workflows2.compiler.compiler import COMPUTE_OPERATORS
from workflows2.compiler.conditions import COMPARE_OPERATORS, CONDITION_OPERATORS
from workflows2.compiler.expr import ALLOWED_REF_ROOTS, EXPRESSION_FUNCTION_GROUPS
from workflows2.events.registry import get_event_registry


def _sorted_or_none(value: Any) -> list[str] | None:
    if value is None:
        return None
    return sorted(str(x) for x in value)


def build_context_catalog() -> dict[str, Any]:
    """Return the metadata catalog consumed by the Workflow 2 editor."""
    reg = get_event_registry()

    events = [
        {
            'key': spec.key,
            'title': getattr(spec, 'title', '') or spec.key,
            'group': spec.key.split('.', 1)[0] if '.' in spec.key else spec.key,
            'description': spec.description,
            'allowed_step_types': (
                sorted(spec.allowed_step_types)
                if spec.allowed_step_types is not None
                else None
            ),
            'context_vars': [
                {
                    'path': variable.path,
                    'title': getattr(variable, 'title', '') or variable.path,
                    'type': variable.type,
                    'description': variable.description,
                    'example': variable.example,
                }
                for variable in (spec.context_vars or [])
            ],
        }
        for spec in reg.all_specs()
    ]

    steps = [
        {
            'type': step.type,
            'title': step.title,
            'description': step.description,
            'category': step.category,
            'fields': [
                {
                    'key': field.key,
                    'title': field.title,
                    'description': field.description,
                    'required': bool(field.required),
                    'field_kind': field.field_kind,
                    'default': field.default,
                    'scaffold': field.scaffold,
                    'enum': list(field.enum) if field.enum is not None else None,
                    'group': field.group,
                }
                for field in step.fields
            ],
            'scaffold': {
                'type': step.type,
                **{
                    field.key: (field.scaffold if field.scaffold is not None else field.default)
                    for field in step.fields
                    if field.required
                },
            },
        }
        for step in step_specs()
    ]

    presets = [
        {
            'id': preset.id,
            'title': preset.title,
            'description': preset.description,
            'areas': sorted(getattr(preset, 'areas', set())),
            'triggers': _sorted_or_none(getattr(preset, 'triggers', None)),
            'step_types': _sorted_or_none(getattr(preset, 'step_types', None)),
        }
        for preset in PRESETS
    ]

    return {
        'events': sorted(events, key=lambda x: x['key']),
        'steps': steps,
        'presets': presets,
        'trigger_sources': build_trigger_source_catalog(),
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
            'version': 5,
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
