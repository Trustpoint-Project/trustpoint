"""Validation for Approval step params."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error, positive_int


def validate_approval_step(*, idx: int, params: dict[str, Any], errors: list[str]) -> None:
    """Validate Approval step parameters."""
    timeout = params.get('timeoutSecs')
    if timeout is not None and not positive_int(timeout):
        error(errors, _('Step #%s (Approval): timeoutSecs must be a positive integer if provided.') % idx)

    role = params.get('approverRole')
    if role is not None and not isinstance(role, str):
        error(errors, _('Step #%s (Approval): approverRole must be a string if provided.') % idx)
