"""Event-dependent validation policies for allowed step types."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error, get_primary_event, get_steps, registered_step_types


def allowed_step_types_for_event(payload: dict[str, Any]) -> set[str] | None:
    """Return allowed step types for the current event, or None to allow all.

    Current policy:
    - handler == "device_action": disallow Approval
    """
    registered = registered_step_types()
    handler, _protocol, _operation = get_primary_event(payload)

    if handler == 'device_action':
        return {t for t in registered if t != 'Approval'}

    return None


def validate_step_types_allowed(payload: dict[str, Any], errors: list[str]) -> None:
    """Validate the policy that restricts step types based on the event handler."""
    allowed = allowed_step_types_for_event(payload)
    if allowed is None:
        return

    steps = get_steps(payload)
    for i, s in enumerate(steps, start=1):
        if not isinstance(s, dict):
            continue
        st = s.get('type')
        if isinstance(st, str) and st and st not in allowed:
            handler, protocol, operation = get_primary_event(payload)
            error(
                errors,
                _(
                    'Step #%s: type "%s" is not allowed for event "%s" (protocol="%s", operation="%s").'
                )
                % (i, st, handler or '', protocol or '', operation or ''),
            )
