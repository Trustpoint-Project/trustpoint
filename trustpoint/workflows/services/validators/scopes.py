"""Validation for workflow scopes."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error


def validate_scopes(payload: dict[str, Any], errors: list[str]) -> None:
    """Validate scopes shape and ensure at least one scope is present."""
    scopes = payload.get('scopes')
    if isinstance(scopes, dict):
        total = sum(len(scopes.get(k, [])) for k in ('ca_ids', 'domain_ids', 'device_ids'))
        if total == 0:
            error(errors, _('At least one scope (CA/Domain/Device) is required.'))
        return

    if isinstance(scopes, list):
        if not scopes:
            error(errors, _('At least one scope (CA/Domain/Device) is required.'))
        return

    error(errors, _('Invalid scopes format.'))
