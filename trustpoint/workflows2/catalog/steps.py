"""Static metadata that describes supported Workflow 2 step types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _

from workflows2.compiler.step_types import StepTypes

TranslatedText = str | Promise

FieldKind = Literal[
    'string',
    'text',
    'int',
    'bool',
    'template',
    'mapping',
    'list',
    'condition',
    'condition_list',
    'compare_operator',
    'http_method',
    'outcome',
    'step_type',
    'vars_mapping',
    'compute_mapping',
    'capture_mapping',
]


@dataclass(frozen=True)
class StepField:
    """Describe one editable field on a step type."""

    key: str
    title: TranslatedText
    description: TranslatedText
    required: bool = False
    field_kind: FieldKind = 'string'
    default: Any = None
    scaffold: Any = None
    enum: tuple[str, ...] | None = None
    group: str = ''


@dataclass(frozen=True)
class StepSpec:
    """Describe a supported step type for the editor catalog."""

    type: str
    title: TranslatedText
    description: TranslatedText
    category: str
    fields: list[StepField]


COMMON_STEP_FIELDS: tuple[StepField, ...] = (
    StepField(
        key='type',
        title=_('type'),
        description=_('Step type.'),
        required=True,
        field_kind='step_type',
        enum=tuple(sorted(StepTypes.all())),
    ),
    StepField(
        key='title',
        title=_('title'),
        description=_('Optional human-readable UI label.'),
        required=False,
        field_kind='string',
        default='',
    ),
)


def step_specs() -> list[StepSpec]:
    """Return the step definitions shown in the Workflow 2 editor."""
    return [
        StepSpec(
            type='logic',
            title=_('Logic routing'),
            description=_('Evaluate cases and return an outcome string.'),
            category='step',
            fields=[
                StepField(
                    key='cases',
                    title=_('cases'),
                    description=_('Ordered list of conditions that each produce an outcome.'),
                    required=True,
                    field_kind='condition_list',
                    scaffold=[
                        {
                            'when': {
                                'compare': {
                                    'left': '${vars.status}',
                                    'op': '==',
                                    'right': 200,
                                }
                            },
                            'outcome': 'ok',
                        }
                    ],
                ),
                StepField(
                    key='default',
                    title=_('default outcome'),
                    description=_('Outcome returned when no case matches.'),
                    required=True,
                    field_kind='outcome',
                    default='fail',
                ),
            ],
        ),
        StepSpec(
            type='webhook',
            title=_('Webhook'),
            description=_('HTTP request via adapter.'),
            category='step',
            fields=[
                StepField(
                    key='method',
                    title=_('method'),
                    description=_('HTTP method.'),
                    required=True,
                    field_kind='http_method',
                    default='POST',
                    enum=('GET', 'POST', 'PUT', 'PATCH', 'DELETE'),
                ),
                StepField(
                    key='url',
                    title=_('url'),
                    description=_('Request URL (templated).'),
                    required=True,
                    field_kind='template',
                    default='https://example.com/api',
                ),
                StepField(
                    key='headers',
                    title=_('headers'),
                    description=_('Request headers mapping.'),
                    required=False,
                    field_kind='mapping',
                    scaffold={'x-request-id': 'request-id'},
                ),
                StepField(
                    key='body',
                    title=_('body'),
                    description=_('Request body (YAML object, list, string, or null).'),
                    required=False,
                    field_kind='mapping',
                    scaffold={'example': 'value'},
                ),
                StepField(
                    key='timeout_seconds',
                    title=_('timeout_seconds'),
                    description=_('Timeout in seconds.'),
                    required=False,
                    field_kind='int',
                    default=10,
                ),
                StepField(
                    key='capture',
                    title=_('capture'),
                    description=_('Capture response fields into vars using vars.<name>: <source>.'),
                    required=False,
                    field_kind='capture_mapping',
                    scaffold={'vars.http_status': 'status_code'},
                ),
            ],
        ),
        StepSpec(
            type='email',
            title=_('Email'),
            description=_('Send an email via adapter.'),
            category='step',
            fields=[
                StepField(
                    key='to',
                    title=_('to'),
                    description=_('Recipient list.'),
                    required=True,
                    field_kind='list',
                    scaffold=['user@example.com'],
                ),
                StepField(
                    key='subject',
                    title=_('subject'),
                    description=_('Email subject (templated).'),
                    required=True,
                    field_kind='template',
                    default='Subject',
                ),
                StepField(
                    key='body',
                    title=_('body'),
                    description=_('Email body (templated).'),
                    required=True,
                    field_kind='text',
                    default='Body',
                ),
                StepField(
                    key='cc',
                    title=_('cc'),
                    description=_('CC recipient list.'),
                    required=False,
                    field_kind='list',
                    scaffold=['cc@example.com'],
                ),
                StepField(
                    key='bcc',
                    title=_('bcc'),
                    description=_('BCC recipient list.'),
                    required=False,
                    field_kind='list',
                    scaffold=['bcc@example.com'],
                ),
            ],
        ),
        StepSpec(
            type='approval',
            title=_('Approval'),
            description=_('Pause until external approval decision.'),
            category='step',
            fields=[
                StepField(
                    key='approved_outcome',
                    title=_('approved_outcome'),
                    description=_('Outcome for approve.'),
                    required=True,
                    field_kind='outcome',
                    default='approved',
                ),
                StepField(
                    key='rejected_outcome',
                    title=_('rejected_outcome'),
                    description=_('Outcome for reject.'),
                    required=True,
                    field_kind='outcome',
                    default='rejected',
                ),
                StepField(
                    key='timeout_seconds',
                    title=_('timeout_seconds'),
                    description=_('Optional timeout in seconds.'),
                    required=False,
                    field_kind='int',
                    default=3600,
                ),
            ],
        ),
        StepSpec(
            type='set',
            title=_('Set vars'),
            description=_('Write literal or templated values into vars.'),
            category='step',
            fields=[
                StepField(
                    key='vars',
                    title=_('vars'),
                    description=_('Mapping of vars.<name> to literal or templated values.'),
                    required=True,
                    field_kind='vars_mapping',
                    scaffold={'vars.result': 'value'},
                ),
            ],
        ),
        StepSpec(
            type='compute',
            title=_('Compute vars'),
            description=_('Assign vars via safe expressions or YAML operator mappings.'),
            category='step',
            fields=[
                StepField(
                    key='set',
                    title=_('set'),
                    description=_('Mapping of vars.<name> to an expression or YAML operator mapping.'),
                    required=True,
                    field_kind='compute_mapping',
                    scaffold={
                        'vars.result': {
                            'add': ['${vars.a}', 1],
                        }
                    },
                ),
            ],
        ),
    ]
