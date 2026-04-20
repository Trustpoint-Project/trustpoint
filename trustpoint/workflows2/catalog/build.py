"""Build the editor context catalog for the Workflow 2 frontend."""

from __future__ import annotations

from typing import Any

from django.utils.encoding import force_str
from django.utils.translation import gettext as _

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


def _text(value: Any, fallback: str = '') -> str:
    return force_str(value if value is not None else fallback)


def _event_group_key(spec: Any) -> str:
    explicit = _text(getattr(spec, 'group', ''), '').strip()
    if explicit:
        return explicit
    key = _text(getattr(spec, 'key', ''), '').strip()
    return key.split('.', 1)[0] if '.' in key else key


def _event_group_title(spec: Any) -> str:
    explicit = _text(getattr(spec, 'group_title', ''), '').strip()
    if explicit:
        return explicit
    group_key = _event_group_key(spec)
    return group_key.replace('_', ' ').replace('.', ' ').strip().title() or _text(getattr(spec, 'key', ''))


def build_event_catalog() -> list[dict[str, Any]]:
    """Return the normalized event metadata consumed by editor UI surfaces."""
    reg = get_event_registry()
    events: list[dict[str, Any]] = []

    for spec in reg.all_specs():
        context_vars = [variable.to_dict() for variable in (spec.context_vars or [])]
        key = _text(spec.key).strip()
        title = _text(getattr(spec, 'title', '') or key).strip() or key
        description = _text(getattr(spec, 'description', ''), '')
        group = _event_group_key(spec)
        group_title = _event_group_title(spec)
        keywords = [
            keyword
            for raw_keyword in (getattr(spec, 'keywords', ()) or ())
            if (keyword := _text(raw_keyword).strip())
        ]
        search_chunks = [
            key,
            title,
            group,
            group_title,
        ]
        events.append(
            {
                'key': key,
                'title': title,
                'group': group,
                'group_title': group_title,
                'description': description,
                'keywords': keywords,
                'search_text': ' '.join(chunk for chunk in search_chunks if chunk).lower(),
                'allowed_step_types': (
                    sorted(spec.allowed_step_types)
                    if spec.allowed_step_types is not None
                    else None
                ),
                'context_vars': context_vars,
            }
        )

    return sorted(events, key=lambda item: (item['group_title'].lower(), item['title'].lower(), item['key']))


def build_context_catalog() -> dict[str, Any]:
    """Return the metadata catalog consumed by the Workflow 2 editor."""
    events = build_event_catalog()

    steps = [
        {
            'type': step.type,
            'title': _text(step.title),
            'description': _text(step.description),
            'category': step.category,
            'fields': [
                {
                    'key': field.key,
                    'title': _text(field.title),
                    'description': _text(field.description),
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
            'title': _text(preset.title),
            'description': _text(preset.description),
            'areas': sorted(getattr(preset, 'areas', set())),
            'triggers': _sorted_or_none(getattr(preset, 'triggers', None)),
            'step_types': _sorted_or_none(getattr(preset, 'step_types', None)),
        }
        for preset in PRESETS
    ]

    return {
        'events': events,
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
            'version': 7,
            'common_step_fields': [
                {
                    'key': f.key,
                    'title': _text(f.title),
                    'description': _text(f.description),
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
            'i18n': {
                'guide_trigger_browse_description': _(
                    'Search documented triggers by name, key, or group.'
                ),
                'guide_trigger_browse_title': _('Browse triggers'),
                'guide_trigger_current_title': _('Current trigger'),
                'guide_trigger_empty': _('No documented triggers available.'),
                'guide_trigger_group_label': _('Group'),
                'guide_trigger_none': _('None'),
                'guide_trigger_no_matches': _('No matching triggers.'),
                'guide_trigger_note': _('Choose a documented trigger to unlock event-specific help.'),
                'guide_trigger_search_placeholder': _('Search triggers'),
                'guide_trigger_selected_action': _('Selected'),
                'guide_trigger_selected_label': _('Selected'),
                'guide_trigger_select_action': _('Use this trigger'),
            },
        },
    }
