"""Register the built-in Workflow 2 trigger definitions."""

from __future__ import annotations

from django.utils.translation import gettext_lazy as _

from workflows2.events.context_catalog import (
    CERTIFICATE_CONTEXT,
    DEVICE_CONTEXT,
    DEVICE_UPDATE_CONTEXT,
    EST_CONTEXT,
    REST_CONTEXT,
    SOURCE_CONTEXT,
    merge,
)
from workflows2.events.policies import STEPSET_AUTOMATION, STEPSET_GATED_ENROLLMENT
from workflows2.events.registry import EventSpec, get_event_registry
from workflows2.events.triggers import Triggers


def register_builtin_events() -> None:
    """Populate the global event registry with built-in triggers."""
    reg = get_event_registry()

    reg.register(
        EventSpec(
            key=Triggers.DEVICE_CREATED,
            title=_('Device created'),
            description=_('A device object was created.'),
            group='device_lifecycle',
            group_title=_('Device lifecycle'),
            keywords=('device', 'inventory', 'create', 'created'),
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.DEVICE_DELETED,
            title=_('Device deleted'),
            description=_('A device object was deleted.'),
            group='device_lifecycle',
            group_title=_('Device lifecycle'),
            keywords=('device', 'inventory', 'delete', 'deleted'),
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.DEVICE_UPDATED,
            title=_('Device updated'),
            description=_('A device object was updated.'),
            group='device_lifecycle',
            group_title=_('Device lifecycle'),
            keywords=('device', 'inventory', 'update', 'updated', 'before', 'after', 'changes'),
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, DEVICE_UPDATE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.CERTIFICATE_ISSUED,
            title=_('Certificate issued'),
            description=_('A certificate was issued for a managed credential.'),
            group='certificate_lifecycle',
            group_title=_('Certificate lifecycle'),
            keywords=('certificate', 'credential', 'issue', 'issued', 'enroll'),
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, CERTIFICATE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.CERTIFICATE_REVOKED,
            title=_('Certificate revoked'),
            description=_('A managed certificate was revoked.'),
            group='certificate_lifecycle',
            group_title=_('Certificate lifecycle'),
            keywords=('certificate', 'credential', 'revoke', 'revoked'),
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, CERTIFICATE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.EST_SIMPLEENROLL,
            title=_('EST simpleenroll'),
            description=_('EST simpleenroll request received.'),
            group='est_requests',
            group_title='EST',
            keywords=('est', 'simpleenroll', 'enrollment', 'request'),
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.EST_SIMPLEREENROLL,
            title=_('EST simplereenroll'),
            description=_('EST simplereenroll request received.'),
            group='est_requests',
            group_title='EST',
            keywords=('est', 'simplereenroll', 'reenrollment', 'request'),
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.REST_ENROLL,
            title=_('REST enroll'),
            description=_('REST enroll request received.'),
            group='rest_requests',
            group_title='REST',
            keywords=('rest', 'enroll', 'enrollment', 'request'),
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, REST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.REST_REENROLL,
            title=_('REST reenroll'),
            description=_('REST reenroll request received.'),
            group='rest_requests',
            group_title='REST',
            keywords=('rest', 'reenroll', 'reenrollment', 'request'),
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, REST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key='workflows2.test',
            title=_('Workflow test'),
            description=_('Internal test trigger that allows all supported step types.'),
            group='internal',
            group_title=_('Internal'),
            keywords=('test', 'internal', 'workflows2'),
            allowed_step_types=None,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT, SOURCE_CONTEXT),
        )
    )
