# workflows2/catalog/steps.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from workflows2.compiler.step_types import StepTypes

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
    key: str
    title: str
    description: str
    required: bool = False
    field_kind: FieldKind = 'string'
    default: Any = None
    scaffold: Any = None
    enum: tuple[str, ...] | None = None
    group: str = ''


@dataclass(frozen=True)
class StepSpec:
    type: str
    title: str
    description: str
    category: str
    fields: list[StepField]


COMMON_STEP_FIELDS: tuple[StepField, ...] = (
    StepField(
        key='type',
        title='type',
        description='Step type.',
        required=True,
        field_kind='step_type',
        enum=tuple(sorted(StepTypes.all())),
    ),
    StepField(
        key='title',
        title='title',
        description='Optional human-readable UI label.',
        required=False,
        field_kind='string',
        default='',
    ),
)


def step_specs() -> list[StepSpec]:
    return [
        StepSpec(
            type='logic',
            title='Logic routing',
            description='Evaluate cases and return an outcome string.',
            category='step',
            fields=[
                StepField(
                    key='cases',
                    title='cases',
                    description='Ordered list of conditions that each produce an outcome.',
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
                    title='default outcome',
                    description='Outcome returned when no case matches.',
                    required=True,
                    field_kind='outcome',
                    default='fail',
                ),
            ],
        ),
        StepSpec(
            type='webhook',
            title='Webhook',
            description='HTTP request via adapter.',
            category='step',
            fields=[
                StepField(
                    key='method',
                    title='method',
                    description='HTTP method.',
                    required=True,
                    field_kind='http_method',
                    default='POST',
                    enum=('GET', 'POST', 'PUT', 'PATCH', 'DELETE'),
                ),
                StepField(
                    key='url',
                    title='url',
                    description='Request URL (templated).',
                    required=True,
                    field_kind='template',
                    default='https://example.com/api',
                ),
                StepField(
                    key='headers',
                    title='headers',
                    description='Request headers mapping.',
                    required=False,
                    field_kind='mapping',
                    scaffold={'x-request-id': 'request-id'},
                ),
                StepField(
                    key='body',
                    title='body',
                    description='Request body (YAML object, list, string, or null).',
                    required=False,
                    field_kind='mapping',
                    scaffold={'example': 'value'},
                ),
                StepField(
                    key='timeout_seconds',
                    title='timeout_seconds',
                    description='Timeout in seconds.',
                    required=False,
                    field_kind='int',
                    default=10,
                ),
                StepField(
                    key='capture',
                    title='capture',
                    description='Capture response fields into vars using vars.<name>: <source>.',
                    required=False,
                    field_kind='capture_mapping',
                    scaffold={'vars.http_status': 'status_code'},
                ),
            ],
        ),
        StepSpec(
            type='email',
            title='Email',
            description='Send an email via adapter.',
            category='step',
            fields=[
                StepField(
                    key='to',
                    title='to',
                    description='Recipient list.',
                    required=True,
                    field_kind='list',
                    scaffold=['user@example.com'],
                ),
                StepField(
                    key='subject',
                    title='subject',
                    description='Email subject (templated).',
                    required=True,
                    field_kind='template',
                    default='Subject',
                ),
                StepField(
                    key='body',
                    title='body',
                    description='Email body (templated).',
                    required=True,
                    field_kind='text',
                    default='Body',
                ),
                StepField(
                    key='cc',
                    title='cc',
                    description='CC recipient list.',
                    required=False,
                    field_kind='list',
                    scaffold=['cc@example.com'],
                ),
                StepField(
                    key='bcc',
                    title='bcc',
                    description='BCC recipient list.',
                    required=False,
                    field_kind='list',
                    scaffold=['bcc@example.com'],
                ),
            ],
        ),
        StepSpec(
            type='approval',
            title='Approval',
            description='Pause until external approval decision.',
            category='step',
            fields=[
                StepField(
                    key='approved_outcome',
                    title='approved_outcome',
                    description='Outcome for approve.',
                    required=True,
                    field_kind='outcome',
                    default='approved',
                ),
                StepField(
                    key='rejected_outcome',
                    title='rejected_outcome',
                    description='Outcome for reject.',
                    required=True,
                    field_kind='outcome',
                    default='rejected',
                ),
                StepField(
                    key='timeout_seconds',
                    title='timeout_seconds',
                    description='Optional timeout in seconds.',
                    required=False,
                    field_kind='int',
                    default=3600,
                ),
            ],
        ),
        StepSpec(
            type='set',
            title='Set vars',
            description='Write literal or templated values into vars.',
            category='step',
            fields=[
                StepField(
                    key='vars',
                    title='vars',
                    description='Mapping of vars.<name> to literal or templated values.',
                    required=True,
                    field_kind='vars_mapping',
                    scaffold={'vars.result': 'value'},
                ),
            ],
        ),
        StepSpec(
            type='compute',
            title='Compute vars',
            description='Assign vars via safe expressions or YAML operator mappings.',
            category='step',
            fields=[
                StepField(
                    key='set',
                    title='set',
                    description='Mapping of vars.<name> to an expression or YAML operator mapping.',
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
