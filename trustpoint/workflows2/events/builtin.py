# workflows2/events/builtin.py
from __future__ import annotations

from workflows2.events.context_catalog import DEVICE_CONTEXT, EST_CONTEXT, merge
from workflows2.events.policies import STEPSET_AUTOMATION, STEPSET_GATED_ENROLLMENT
from workflows2.events.registry import EventSpec, get_event_registry
from workflows2.events.triggers import Triggers


def register_builtin_events() -> None:
    reg = get_event_registry()

    reg.register(
        EventSpec(
            key=Triggers.DEVICE_CREATED,
            title="Device created",
            description="A device object was created.",
            allowed_step_types=STEPSET_AUTOMATION,
            context_vars=DEVICE_CONTEXT,
        )
    )

    reg.register(
        EventSpec(
            key=Triggers.EST_SIMPLEENROLL,
            title="EST simpleenroll",
            description="EST simpleenroll request received.",
            allowed_step_types=STEPSET_GATED_ENROLLMENT,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT),
        )
    )

    reg.register(
        EventSpec(
            key="workflows2.test",
            title="Workflow test",
            description="Internal test trigger that allows all supported step types.",
            allowed_step_types=None,
            context_vars=merge(DEVICE_CONTEXT, EST_CONTEXT),
        )
    )
