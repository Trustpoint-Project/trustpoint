"""Validation helpers for the workflow wizard payload (server-side)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from django.utils.translation import gettext as _

from util.email import normalize_addresses
from workflows.events import Events
from workflows.services.executors.factory import StepExecutorFactory

# ----------------------------- helpers -----------------------------


def _error(errors: list[str], msg: str) -> None:
    errors.append(msg)


_SEGMENT_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.')


def _is_dotpath(s: str) -> bool:
    """Return True if `s` is a valid dot-path like 'serial_number' or 'http.status' (bare path; no prefix)."""
    if not isinstance(s, str) or not s:
        return False
    if any(ch not in _SEGMENT_CHARS for ch in s):
        return False
    parts = s.split('.')
    return all(p and (p[0].isalpha() or p[0] == '_') and p.replace('_', '').isalnum() for p in parts)


def _is_bare_var_path(s: str) -> bool:
    """Bare variable path (no 'vars.'), at least one segment, dot-separated."""
    return _is_dotpath(s)


def _is_http_url(s: str) -> bool:
    return isinstance(s, str) and s.strip().lower().startswith(('http://', 'https://'))


def _known_event_triples() -> set[tuple[str, str, str]]:
    """Return set of (handler, protocol_lc, operation) from Events (protocol normalized)."""
    triples: set[tuple[str, str, str]] = set()
    for t in Events.all():
        h = (t.handler or '').strip()
        p = (t.protocol or '').strip().lower()
        o = (t.operation or '').strip()
        triples.add((h, p, o))
        if not p and not o:
            triples.add((h, '', ''))
    return triples


def _registered_step_types() -> set[str]:
    """Return the set of registered step type identifiers.

    Returns:
        set[str]: Step type names as registered with the executor factory.
    """
    return StepExecutorFactory.registered_types()


def _positive_int(value: Any) -> bool:
    try:
        return int(value) > 0
    except Exception:  # noqa: BLE001
        return False


# --------------------------- field checks ---------------------------

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
    ok = True
    msg: str | None = None

    if val is None:
        return ok, msg

    if not isinstance(val, Mapping):
        return False, _('auth must be an object.')

    t = (val.get('type') or '').strip().lower()
    if t == 'basic':
        if not isinstance(val.get('username'), str) or not isinstance(val.get('password'), str):
            ok = False
            msg = _('auth.basic requires username and password (strings).')
    elif t == 'bearer':
        if not isinstance(val.get('token'), str) or not val.get('token'):
            ok = False
            msg = _('auth.bearer requires a non-empty token (string).')
    else:
        ok = False
        msg = _('auth.type must be "basic" or "bearer".')

    return ok, msg


def _is_valid_from_path(s: str) -> bool:
    """Allow: status | text | json[.a.b.0] | headers[.x_y] (no dashes in dot lookups)."""
    if not isinstance(s, str) or not s:
        return False
    if s in {'status', 'text', 'json', 'headers'}:
        return True
    if s.startswith(('json.', 'headers.')):
        # After the prefix, enforce dotpath (letters/digits/_/.)
        return _is_dotpath(s)
    return False


# ---------------------------- per step -----------------------------


def _validate_email_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    recips_raw = params.get('recipients', '')
    to: Sequence[str] = normalize_addresses(recips_raw)
    if not to:
        _error(errors, _('Step #%s (Email): at least one recipient is required.') % idx)

    template = (params.get('template') or '').strip()
    subject = (params.get('subject') or '').strip()
    body = (params.get('body') or '').strip()

    # Template mode skips subject/body requirements.
    if template:
        return
    if not subject:
        _error(errors, _('Step #%s (Email): subject is required in custom mode.') % idx)
    if not body:
        _error(errors, _('Step #%s (Email): body is required in custom mode.') % idx)


def _validate_approval_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    timeout = params.get('timeoutSecs')
    if timeout is not None and not _positive_int(timeout):
        _error(errors, _('Step #%s (Approval): timeoutSecs must be a positive integer if provided.') % idx)
    role = params.get('approverRole')
    if role is not None and not isinstance(role, str):
        _error(errors, _('Step #%s (Approval): approverRole must be a string if provided.') % idx)


def _validate_timer_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    delay = params.get('delaySecs')
    if delay is None or not _positive_int(delay):
        _error(errors, _('Step #%s (Timer): delaySecs is required and must be a positive integer.') % idx)


def _validate_condition_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    expr = params.get('expression')
    if not isinstance(expr, str) or not expr.strip():
        _error(errors, _('Step #%s (Condition): expression is required (string).') % idx)


def _validate_webhook_basic_fields(
    idx: int,
    params: dict[str, Any],
    errors: list[str],
) -> None:
    """URL, method, headers, body for webhook step."""
    # url
    url = (params.get('url') or '').strip()
    if not _is_http_url(url):
        _error(errors, _('Step #%s (Webhook): url is required and must start with http:// or https://.') % idx)

    # method
    method = (params.get('method') or 'POST').upper()
    if method not in _ALLOWED_METHODS:
        _error(
            errors,
            _('Step #%s (Webhook): method must be one of %s.') % (idx, ', '.join(sorted(_ALLOWED_METHODS))),
        )

    # headers
    headers = params.get('headers')
    if headers is not None and not _validate_headers_dict(headers):
        _error(
            errors,
            _('Step #%s (Webhook): headers must be an object of string keys and string/number values.') % idx,
        )

    # body
    body = params.get('body')
    if method == 'GET' and body not in (None, '', {}):
        _error(errors, _('Step #%s (Webhook): body is not allowed for GET requests.') % idx)
    elif body is not None and not isinstance(body, (str, Mapping, list)):
        _error(errors, _('Step #%s (Webhook): body must be a string, object, or array if provided.') % idx)


def _validate_webhook_auth_and_timeout(
    idx: int,
    params: dict[str, Any],
    errors: list[str],
) -> None:
    """Auth and timeout for webhook step."""
    ok, msg = _validate_webhook_auth(params.get('auth'))
    if not ok:
        _error(errors, _('Step #%s (Webhook): %s') % (idx, msg or _('invalid auth')))

    # timeout
    tmo = params.get('timeoutSecs')
    if tmo is None:
        return

    try:
        tmo_i = int(tmo)
    except Exception:  # noqa: BLE001
        _error(errors, _('Step #%s (Webhook): timeoutSecs must be an integer (seconds).') % idx)
        return

    if not (1 <= tmo_i <= _WEBHOOK_MAX_TIMEOUT_SECS):
        _error(
            errors,
            _('Step #%s (Webhook): timeoutSecs must be between 1 and 120.') % idx,
        )


def _validate_webhook_result_mapping(
    idx: int,
    params: dict[str, Any],
    errors: list[str],
) -> None:
    """result_to/result_source/exports for webhook step."""
    # result_to/result_source (optional but must be valid if present)
    result_to = (params.get('result_to') or '').strip()
    if result_to and not _is_bare_var_path(result_to):
        _error(
            errors,
            _('Step #%s (Webhook): result_to must be a variable path like "serial_number" or "http.status".') % idx,
        )

    result_source = (params.get('result_source') or 'auto').strip().lower()
    if result_source and result_source not in {'auto', 'json', 'text', 'status', 'headers'}:
        _error(
            errors,
            _('Step #%s (Webhook): result_source must be one of auto/json/text/status/headers.') % idx,
        )

    # exports (fine-grained mappings)
    if 'export' in params and 'exports' not in params:
        _error(
            errors,
            _(
                'Step #%s (Webhook): use "exports": [ {"from_path":"json.foo","to_path":"my.foo"} ] '
                'instead of legacy "export" mapping.'
            )
            % idx,
        )

    exports = params.get('exports') or []
    if not isinstance(exports, Iterable):
        _error(errors, _('Step #%s (Webhook): exports must be an array if provided.') % idx)
        return

    seen_to: set[str] = set()
    for j, e in enumerate(exports, start=1):
        if not isinstance(e, Mapping):
            _error(errors, _('Step #%s (Webhook): export #%s must be an object.') % (idx, j))
            continue

        fp = (e.get('from_path') or '').strip()
        tp = (e.get('to_path') or '').strip()

        if not _is_valid_from_path(fp):
            _error(
                errors,
                _(
                    'Step #%s (Webhook): export #%s from_path must be one of '
                    '"status", "text", "json[.path]" or "headers[.path]".'
                )
                % (idx, j),
            )

        if not _is_bare_var_path(tp):
            _error(
                errors,
                _(
                    'Step #%s (Webhook): export #%s to_path must be a variable path like '
                    '"serial_number" or "http.status" (no "vars." prefix).'
                )
                % (idx, j),
            )
        elif tp in seen_to:
            _error(errors, _('Step #%s (Webhook): duplicate to_path "%s" in exports.') % (idx, tp))
        else:
            seen_to.add(tp)


def _validate_webhook_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    _validate_webhook_basic_fields(idx, params, errors)
    _validate_webhook_auth_and_timeout(idx, params, errors)
    _validate_webhook_result_mapping(idx, params, errors)


# ---------------------------- top-level -----------------------------


def _validate_name(payload: dict[str, Any], errors: list[str]) -> None:
    name = payload.get('name')
    if not isinstance(name, str) or not name.strip():
        _error(errors, _('Name is required.'))


def _validate_events(payload: dict[str, Any], errors: list[str]) -> None:
    events = payload.get('events')
    if not isinstance(events, list) or not events:
        _error(errors, _('At least one event is required.'))
        return

    triples = _known_event_triples()
    for i, t in enumerate(events, start=1):
        if not isinstance(t, dict):
            _error(errors, _('Event #%s is not an object.') % i)
            continue

        handler = (t.get('handler') or '').strip()
        protocol = (t.get('protocol') or '').strip().lower()  # canonical lower
        operation = (t.get('operation') or '').strip()

        if not handler:
            _error(errors, _('Event #%s: handler is required.') % i)
            continue

        needs_po = handler == 'certificate_request'
        if needs_po and (not protocol or not operation):
            _error(
                errors,
                _('Event #%s: protocol and operation are required for certificate_request.') % i,
            )

        key = (handler, protocol, operation) if needs_po else (handler, protocol or '', operation or '')
        if key not in triples:
            _error(errors, _('Event #%s: unknown handler/protocol/operation combination.') % i)


def _validate_single_step(
    idx: int,
    step: Any,
    registered: set[str],
    errors: list[str],
) -> None:
    """Validate a single step object."""
    if not isinstance(step, dict):
        _error(errors, _('Step #%s is not an object.') % idx)
        return

    stype = step.get('type')
    if stype not in registered:
        _error(errors, _('Step #%s: unknown type "%s".') % (idx, stype))
        return

    params = step.get('params') or {}
    if not isinstance(params, dict):
        _error(errors, _('Step #%s: params must be an object.') % idx)
        return

    if stype == 'Email':
        _validate_email_step(idx, params, errors)
    elif stype == 'Webhook':
        _validate_webhook_step(idx, params, errors)
    elif stype == 'Timer':
        _validate_timer_step(idx, params, errors)
    elif stype == 'Approval':
        _validate_approval_step(idx, params, errors)
    elif stype == 'Condition':
        _validate_condition_step(idx, params, errors)
    # other step types currently have no extra server-side rules


def _validate_steps(payload: dict[str, Any], errors: list[str]) -> None:
    steps = payload.get('steps')
    if not isinstance(steps, list) or not steps:
        _error(errors, _('At least one step is required.'))
        return

    registered = _registered_step_types()
    for i, step in enumerate(steps, start=1):
        _validate_single_step(i, step, registered, errors)


def _validate_scopes(payload: dict[str, Any], errors: list[str]) -> None:
    scopes = payload.get('scopes')
    if isinstance(scopes, dict):
        total = sum(len(scopes.get(k, [])) for k in ('ca_ids', 'domain_ids', 'device_ids'))
        if total == 0:
            _error(errors, _('At least one scope (CA/Domain/Device) is required.'))
        return

    if isinstance(scopes, list):
        if not scopes:
            _error(errors, _('At least one scope (CA/Domain/Device) is required.'))
        return

    _error(errors, _('Invalid scopes format.'))


def validate_wizard_payload(payload: dict[str, Any]) -> list[str]:
    """Validate the wizard JSON (pre-transform).

    Args:
        payload: Raw wizard configuration payload as a dictionary.

    Returns:
        list[str]: A list of human-readable error messages. The list is empty
        if the payload passes all validation checks.
    """
    errors: list[str] = []
    _validate_name(payload, errors)
    _validate_events(payload, errors)
    _validate_steps(payload, errors)
    _validate_scopes(payload, errors)
    return errors
