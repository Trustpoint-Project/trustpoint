"""Validation for Email step params."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from django.utils.translation import gettext as _

from util.email import normalize_addresses
from workflows.services.validators.common import error
from workflows.services.validators.templates import StepFieldValidationCtx, validate_no_future_step_refs, validate_templated_string


def validate_email_step(
    *,
    idx: int,
    params: dict[str, Any],
    errors: list[str],
    key_order: dict[str, int],
) -> None:
    """Validate Email step parameters."""
    recips_raw = params.get('recipients', '')
    to: Sequence[str] = normalize_addresses(recips_raw)
    if not to:
        error(errors, _('Step #%s (Email): at least one recipient is required.') % idx)

    normalize_addresses(params.get('cc'))
    normalize_addresses(params.get('bcc'))

    template = (params.get('template') or '').strip()
    subject = (params.get('subject') or '').strip()
    body = (params.get('body') or '').strip()

    if not template:
        if not subject:
            error(errors, _('Step #%s (Email): subject is required in custom mode.') % idx)
        if not body:
            error(errors, _('Step #%s (Email): body is required in custom mode.') % idx)

    ctx = StepFieldValidationCtx(idx=idx, step_type='Email', errors=errors, key_order=key_order)

    if subject:
        validate_templated_string(idx=idx, step_type='Email', field='subject', value=params.get('subject'), errors=errors)
        validate_no_future_step_refs(ctx, field='subject', value=params.get('subject'))

    if body:
        validate_templated_string(idx=idx, step_type='Email', field='body', value=params.get('body'), errors=errors)
        validate_no_future_step_refs(ctx, field='body', value=params.get('body'))
