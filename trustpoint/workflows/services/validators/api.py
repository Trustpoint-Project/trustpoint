"""Wizard payload validation API (server-side)."""

from __future__ import annotations

from typing import Any

from workflows.services.validators.events import validate_events
from workflows.services.validators.name import validate_name
from workflows.services.validators.policy import validate_step_types_allowed
from workflows.services.validators.scopes import validate_scopes
from workflows.services.validators.steps import ensure_step_ids, validate_steps
from workflows.services.validators.transitions import validate_transitions


def validate_wizard_payload(payload: dict[str, Any]) -> list[str]:
    """Validate the wizard JSON (pre-transform).

    Args:
        payload: Raw wizard configuration payload as a dictionary.

    Returns:
        Human-readable error messages. Empty if valid.
    """
    errors: list[str] = []

    # Failsafe: ensure step ids exist (mutates payload)
    ensure_step_ids(payload, errors)

    validate_name(payload, errors)
    validate_events(payload, errors)

    # Event-dependent step policy (enforced server-side)
    validate_step_types_allowed(payload, errors)

    validate_steps(payload, errors)
    validate_transitions(payload, errors)
    validate_scopes(payload, errors)

    return errors
