"""Validation for steps list and step dispatch."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import (
    error,
    get_steps,
    registered_step_types,
    step_key_order_map,
)
from workflows.services.validators.step_types.approval import validate_approval_step
from workflows.services.validators.step_types.email import validate_email_step
from workflows.services.validators.step_types.logic import validate_logic_step
from workflows.services.validators.step_types.webhook import validate_webhook_step


def ensure_step_ids(payload: dict[str, Any], errors: list[str]) -> None:
    """Ensure every step has an id. If missing, inject 'step-<n>'.

    This is a failsafe for UI bugs; it keeps the backend stable enough to validate.
    """
    steps = get_steps(payload)
    if not steps:
        return

    seen: set[str] = set()
    for i, s in enumerate(steps, start=1):
        if not isinstance(s, dict):
            continue
        sid = s.get('id')
        if not isinstance(sid, str) or not sid.strip():
            sid = f'step-{i}'
            s['id'] = sid
        if sid in seen:
            error(errors, _("Duplicate step id '%s'. Step ids must be unique.") % sid)
        seen.add(sid)


def validate_steps(payload: dict[str, Any], errors: list[str]) -> None:
    """Validate that steps exist, have supported types, and that params are valid."""
    steps = get_steps(payload)
    if not steps:
        error(errors, _('At least one step is required.'))
        return

    registered = registered_step_types()
    key_order = step_key_order_map(payload)

    for idx, step in enumerate(steps, start=1):
        _validate_single_step(
            idx=idx,
            step=step,
            steps=steps,
            registered=registered,
            errors=errors,
            key_order=key_order,
        )

def _validate_single_step(
    *,
    idx: int,
    step: Any,
    steps: list[Any],
    registered: set[str],
    errors: list[str],
    key_order: dict[str, int],
) -> None:
    if not isinstance(step, dict):
        error(errors, _('Step #%s is not an object.') % idx)
        return

    sid = step.get('id')
    if not isinstance(sid, str) or not sid.strip():
        error(errors, _('Step #%s: id is required and must be a string.') % idx)

    stype = step.get('type')
    if stype not in registered:
        error(
            errors,
            _('Step #%s: unknown type "%s". Supported types: %s.')
            % (idx, stype, ', '.join(sorted(registered)) or '<none>'),
        )
        return

    params = step.get('params') or {}
    if not isinstance(params, dict):
        error(errors, _('Step #%s: params must be an object.') % idx)
        return

    if stype == 'Email':
        validate_email_step(idx=idx, params=params, errors=errors, key_order=key_order)
    elif stype == 'Webhook':
        validate_webhook_step(idx=idx, params=params, errors=errors, key_order=key_order)
    elif stype == 'Approval':
        validate_approval_step(idx=idx, params=params, errors=errors)
    elif stype == 'Logic':
        validate_logic_step(
            idx=idx,
            step_id=str(step.get('id') or ''),
            params=params,
            errors=errors,
            steps=steps,
        )
    else:
        return
