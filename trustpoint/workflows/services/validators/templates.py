"""Validation for templated strings and step reference constraints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from django.template import TemplateSyntaxError, engines
from django.utils.translation import gettext as _

from workflows.services.validators.common import error

# Match runtime keys: ctx.steps.<safe_key>
_STEP_REF_RE = re.compile(r'\bctx\.steps\.([A-Za-z_][A-Za-z0-9_]*)\b')

# Detect invalid wildcard usage: ctx.vars.*  (Django templates do not support * wildcard)
_CTX_VARS_WILDCARD_RE = re.compile(r'\bctx\.vars\.\*\b')


@dataclass(frozen=True, slots=True)
class StepFieldValidationCtx:
    """Context passed to no-future-step-reference checks."""

    idx: int
    step_type: str
    errors: list[str]
    key_order: dict[str, int]


def compile_django_template(src: str) -> str | None:
    """Compile a Django template string and return error message, else None."""
    dj = engines['django']
    try:
        dj.from_string(src)
    except TemplateSyntaxError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001
        return str(exc)
    return None


def validate_templated_string(
    *,
    idx: int,
    step_type: str,
    field: str,
    value: Any,
    errors: list[str],
) -> None:
    """Validate a single templated string field."""
    if value is None:
        return
    if not isinstance(value, str):
        error(errors, _('Step #%s (%s): %s must be a string if provided.') % (idx, step_type, field))
        return

    # Allow ctx.vars and ctx.vars.<key>, but reject ctx.vars.* explicitly.
    if _CTX_VARS_WILDCARD_RE.search(value):
        error(
            errors,
            _(
                "Step #%s (%s): '%s' is not valid. Wildcards are not supported. "
                "Use 'ctx.vars' (dict) or a specific key like 'ctx.vars.response'."
            )
            % (idx, step_type, 'ctx.vars.*'),
        )
        return

    msg = compile_django_template(value)
    if msg:
        error(errors, _('Step #%s (%s): template syntax error in %s: %s') % (idx, step_type, field, msg))


def validate_no_future_step_refs(
    ctx: StepFieldValidationCtx,
    *,
    field: str,
    value: Any,
) -> None:
    """Disallow references to ctx.steps.<key> where <key> is future or unknown."""
    if not isinstance(value, str) or not value:
        return

    refs = [m.group(1) for m in _STEP_REF_RE.finditer(value)]
    if not refs:
        return

    unknown = sorted({r for r in refs if r not in ctx.key_order})
    if unknown:
        error(
            ctx.errors,
            _(
                'Step #%s (%s): %s references unknown step key(s): %s. '
                'Step keys must match the runtime-safe form derived from step ids '
                '(e.g. id "step-1" becomes key "step_1").'
            )
            % (ctx.idx, ctx.step_type, field, ', '.join(unknown)),
        )

    future = sorted(
        {r for r in refs if r in ctx.key_order and ctx.key_order[r] >= ctx.idx},
        key=lambda k: ctx.key_order[k],
    )
    if future:
        error(
            ctx.errors,
            _(
                'Step #%s (%s): %s references not-yet-executed step(s): %s. '
                'A step may only reference already executed steps.'
            )
            % (ctx.idx, ctx.step_type, field, ', '.join(future)),
        )
