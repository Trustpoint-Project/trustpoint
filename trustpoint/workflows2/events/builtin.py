"""Register the built-in Workflow 2 trigger definitions."""

from __future__ import annotations

from workflows2.events.context_catalog import (
    DEVICE_CONTEXT,
    DEVICE_DOMAIN_CHANGE_CONTEXT,
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
            title='Device created',
            description='A device object was created.',
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.DEVICE_DOMAIN_CHANGED,
            title='Device domain changed',
            description='A device was moved from one domain to another.',
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, DEVICE_DOMAIN_CHANGE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.DEVICE_DELETED,
            title='Device deleted',
            description='A device object was deleted.',
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=merge(DEVICE_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.EST_SIMPLEENROLL,
            title='EST simpleenroll',
            description='EST simpleenroll request received.',
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.EST_SIMPLEREENROLL,
            title='EST simplereenroll',
            description='EST simplereenroll request received.',
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.REST_ENROLL,
            title='REST enroll',
            description='REST enroll request received.',
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, REST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.REST_REENROLL,
            title='REST reenroll',
            description='REST reenroll request received.',
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, REST_CONTEXT, SOURCE_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key='workflows2.test',
            title='Workflow test',
            description='Internal test trigger that allows all supported step types.',
            allowed_step_types=None,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT, SOURCE_CONTEXT),
        )
    )
