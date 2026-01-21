"""Validation for transitions (if present)."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error, get_steps, get_transitions


def validate_transitions(payload: dict[str, Any], errors: list[str]) -> None:
    """Validate transitions refer to existing step ids."""
    transitions = get_transitions(payload)
    if not transitions:
        return

    steps = get_steps(payload)
    step_ids = {s.get('id') for s in steps if isinstance(s, dict) and isinstance(s.get('id'), str)}

    for i, t in enumerate(transitions, start=1):
        if not isinstance(t, dict):
            error(errors, _('Transition #%s is not an object.') % i)
            continue

        frm = t.get('from')
        to = t.get('to')
        if frm not in step_ids:
            error(errors, _("Transition #%s: from '%s' does not match any step id.") % (i, frm))
        if to not in step_ids:
            error(errors, _("Transition #%s: to '%s' does not match any step id.") % (i, to))
