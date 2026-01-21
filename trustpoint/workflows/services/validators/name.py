"""Validation for workflow name."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error


def validate_name(payload: dict[str, Any], errors: list[str]) -> None:
    """Validate workflow name."""
    name = payload.get('name')
    if not isinstance(name, str) or not name.strip():
        error(errors, _('Name is required.'))
