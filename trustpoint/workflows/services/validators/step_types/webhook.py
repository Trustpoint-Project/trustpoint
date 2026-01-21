"""Validation for Webhook step params."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error, is_bare_var_path, is_dotpath, is_http_url
from workflows.services.validators.templates import StepFieldValidationCtx, validate_no_future_step_refs, validate_templated_string

_ALLOWED_METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}
_WEBHOOK_MAX_TIMEOUT_SECS = 120


def _validate_headers_dict(val: Any) -> bool:
    """Accept {str: str|int|float} to match executor (which renders to str)."""
    if not isinstance(val, Mapping):
        return False
    for k, v in val.items():
        if not isinstance(k, str) or k.strip() == '':
            return False
        if not isinstance(v, (str, int, float)):
            return False
    return True


def _validate_webhook_auth(val: Any) -> tuple[bool, str | None]:
    """Validate webhook auth object."""
    if val is None:
        return True, None

    if not isinstance(val, Mapping):
        return False, _('auth must be an object.')

    t = (val.get('type') or '').strip().lower()
    if t == 'basic':
        if not isinstance(val.get('username'), str) or not isinstance(val.get('password'), str):
            return False, _('auth.basic requires username and password (strings).')
    elif t == 'bearer':
        if not isinstance(val.get('token'), str) or not val.get('token'):
            return False, _('auth.bearer requires a non-empty token (string).')
    else:
        return False, _('auth.type must be "basic" or "bearer".')

    return True, None


def _is_valid_from_path(s: str) -> bool:
    """Allow: status | text | json[.a.b.0] | headers[.x_y]."""
    if not isinstance(s, str) or not s:
        return False
    if s in {'status', 'text', 'json', 'headers'}:
        return True
    if s.startswith(('json.', 'headers.')):
        return is_dotpath(s)
    return False


def _validate_webhook_method_and_body(*, idx: int, method: str, body: Any, errors: list[str]) -> None:
    if method not in _ALLOWED_METHODS:
        error(
            errors,
            _('Step #%s (Webhook): method must be one of %s.') % (idx, ', '.join(sorted(_ALLOWED_METHODS))),
        )
        return

    if method == 'GET' and body not in (None, '', {}):
        error(errors, _('Step #%s (Webhook): body is not allowed for GET requests.') % idx)
        return

    if body is not None and not isinstance(body, (str, Mapping, list)):
        error(errors, _('Step #%s (Webhook): body must be a string, object, or array if provided.') % idx)


def _validate_webhook_headers(*, idx: int, headers: Any, errors: list[str]) -> None:
    if headers is not None and not _validate_headers_dict(headers):
        error(
            errors,
            _('Step #%s (Webhook): headers must be an object of string keys and string/number values.') % idx,
        )


def _validate_webhook_templated_parts(
    *,
    idx: int,
    params: dict[str, Any],
    errors: list[str],
    key_order: dict[str, int],
) -> None:
    ctx = StepFieldValidationCtx(idx=idx, step_type='Webhook', errors=errors, key_order=key_order)

    url_val = params.get('url')
    if isinstance(url_val, str) and url_val.strip():
        validate_templated_string(idx=idx, step_type='Webhook', field='url', value=url_val, errors=errors)
        validate_no_future_step_refs(ctx, field='url', value=url_val)

    headers = params.get('headers')
    if isinstance(headers, Mapping):
        for hk, hv in headers.items():
            if isinstance(hv, str) and hv:
                validate_templated_string(
                    idx=idx,
                    step_type='Webhook',
                    field=f'headers.{hk}',
                    value=hv,
                    errors=errors,
                )
                validate_no_future_step_refs(ctx, field=f'headers.{hk}', value=hv)

    body = params.get('body')
    if isinstance(body, str) and body.strip():
        validate_templated_string(idx=idx, step_type='Webhook', field='body', value=body, errors=errors)
        validate_no_future_step_refs(ctx, field='body', value=body)


def _validate_webhook_auth_and_timeout(*, idx: int, params: dict[str, Any], errors: list[str]) -> None:
    ok, msg = _validate_webhook_auth(params.get('auth'))
    if not ok:
        error(errors, _('Step #%s (Webhook): %s') % (idx, msg or _('invalid auth')))

    tmo = params.get('timeoutSecs')
    if tmo is None:
        return

    try:
        tmo_i = int(tmo)
    except Exception:  # noqa: BLE001
        error(errors, _('Step #%s (Webhook): timeoutSecs must be an integer (seconds).') % idx)
        return

    if not (1 <= tmo_i <= _WEBHOOK_MAX_TIMEOUT_SECS):
        error(errors, _('Step #%s (Webhook): timeoutSecs must be between 1 and 120.') % idx)


def _validate_webhook_variable_mapping(*, idx: int, params: dict[str, Any], errors: list[str]) -> None:
    webhook_variable = (params.get('webhook_variable') or '').strip()
    if webhook_variable and not is_bare_var_path(webhook_variable):
        error(
            errors,
            _(
                "Step #%s (Webhook): webhook_variable must be a variable path like "
                "'serial_number' or 'http.status'."
            )
            % idx,
        )

    result_source = (params.get('result_source') or 'auto').strip().lower()
    if result_source and result_source not in {'auto', 'json', 'text', 'status', 'headers'}:
        error(errors, _('Step #%s (Webhook): result_source must be one of auto/json/text/status/headers.') % idx)

    if 'export' in params and 'exports' not in params:
        error(
            errors,
            _(
                "Step #%s (Webhook): use 'exports': [ {'from_path':'json.foo','to_path':'my.foo'} ] "
                "instead of legacy 'export' mapping."
            )
            % idx,
        )

    exports = params.get('exports') or []
    if not isinstance(exports, Iterable):
        error(errors, _('Step #%s (Webhook): exports must be an array if provided.') % idx)
        return

    seen_to: set[str] = set()
    for j, e in enumerate(exports, start=1):
        if not isinstance(e, Mapping):
            error(errors, _('Step #%s (Webhook): export #%s must be an object.') % (idx, j))
            continue

        fp = (e.get('from_path') or '').strip()
        tp = (e.get('to_path') or '').strip()

        if not _is_valid_from_path(fp):
            error(
                errors,
                _(
                    "Step #%s (Webhook): export #%s from_path must be one of "
                    "'status', 'text', 'json[.path]' or 'headers[.path]'."
                )
                % (idx, j),
            )

        if not is_bare_var_path(tp):
            error(
                errors,
                _(
                    "Step #%s (Webhook): export #%s to_path must be a variable path like "
                    "'serial_number' or 'http.status' (no 'vars.' prefix)."
                )
                % (idx, j),
            )
        elif tp in seen_to:
            error(errors, _("Step #%s (Webhook): duplicate to_path '%s' in exports.") % (idx, tp))
        else:
            seen_to.add(tp)


def validate_webhook_step(
    *,
    idx: int,
    params: dict[str, Any],
    errors: list[str],
    key_order: dict[str, int],
) -> None:
    """Validate Webhook step parameters."""
    url = (params.get('url') or '').strip()
    if not is_http_url(url):
        error(errors, _('Step #%s (Webhook): url is required and must start with http:// or https://.') % idx)

    method = (params.get('method') or 'POST').upper()
    body = params.get('body')
    _validate_webhook_method_and_body(idx=idx, method=method, body=body, errors=errors)

    headers = params.get('headers')
    _validate_webhook_headers(idx=idx, headers=headers, errors=errors)

    _validate_webhook_templated_parts(idx=idx, params=params, errors=errors, key_order=key_order)
    _validate_webhook_auth_and_timeout(idx=idx, params=params, errors=errors)
    _validate_webhook_variable_mapping(idx=idx, params=params, errors=errors)
