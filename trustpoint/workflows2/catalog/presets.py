"""Editor presets for common Workflow 2 authoring tasks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _

TranslatedText = str | Promise

PresetArea = Literal[
    'root',
    'trigger',
    'apply',
    'workflow',
    'workflow.start',
    'workflow.steps',
    'workflow.flow',
]
PresetOperation = Literal[
    'merge_root',
    'set_value',
    'append_list_item',
]


@dataclass(frozen=True)
class Preset:
    """Describe a preset shown in the Workflow 2 guide."""

    id: str
    title: TranslatedText
    description: TranslatedText

    operation: PresetOperation
    payload: Any

    areas: set[PresetArea]
    triggers: set[str] | None = None
    step_types: set[str] | None = None


PRESETS: list[Preset] = [
    Preset(
        id='trigger_block',
        title=_('Trigger block'),
        description=_('Insert a full trigger block with default sources.'),
        operation='merge_root',
        payload={
            'trigger': {
                'on': 'device.created',
                'sources': {
                    'trustpoint': True,
                    'ca_ids': [],
                    'domain_ids': [],
                    'device_ids': [],
                },
            }
        },
        areas={'root'},
    ),
    Preset(
        id='apply_exists_item',
        title=_('Apply: exists condition'),
        description=_('Append an apply rule using exists.'),
        operation='append_list_item',
        payload={
            'exists': '${event.device.domain}',
        },
        areas={'apply', 'root'},
    ),
    Preset(
        id='apply_compare_item',
        title=_('Apply: compare condition'),
        description=_('Append an apply rule using compare.'),
        operation='append_list_item',
        payload={
            'compare': {
                'left': '${vars.status}',
                'op': '==',
                'right': 0,
            }
        },
        areas={'apply', 'root'},
    ),
    Preset(
        id='workflow_skeleton',
        title=_('Workflow skeleton'),
        description=_('Insert a minimal valid workflow with one set step.'),
        operation='merge_root',
        payload={
            'workflow': {
                'start': 'set_result',
                'steps': {
                    'set_result': {
                        'type': 'set',
                        'title': 'Set result',
                        'vars': {
                            'result': 'ok',
                        },
                    }
                },
                'flow': [],
            }
        },
        areas={'root'},
    ),
    Preset(
        id='workflow_start_value',
        title=_('Workflow: start value'),
        description=_('Set workflow.start to a step id.'),
        operation='set_value',
        payload='step_id',
        areas={'workflow', 'workflow.start'},
    ),
    Preset(
        id='flow_linear_edge',
        title=_('Flow: linear edge'),
        description=_('Append a linear flow edge.'),
        operation='append_list_item',
        payload={
            'from': 'step_a',
            'to': 'step_b',
        },
        areas={'workflow.flow'},
    ),
    Preset(
        id='flow_outcome_edge',
        title=_('Flow: outcome edge'),
        description=_('Append an outcome-based flow edge.'),
        operation='append_list_item',
        payload={
            'from': 'step_a',
            'on': 'ok',
            'to': 'step_b',
        },
        areas={'workflow.flow'},
    ),
    Preset(
        id='flow_to_end',
        title=_('Flow: end workflow'),
        description=_('Append a flow edge that ends the workflow via "$end".'),
        operation='append_list_item',
        payload={
            'from': 'step_a',
            'to': '$end',
        },
        areas={'workflow.flow'},
    ),
    Preset(
        id='flow_to_reject',
        title=_('Flow: reject workflow'),
        description=_('Append a flow edge that rejects the workflow via "$reject".'),
        operation='append_list_item',
        payload={
            'from': 'step_a',
            'to': '$reject',
        },
        areas={'workflow.flow'},
    ),
]
