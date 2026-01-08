"""Validation helpers for the workflow wizard payload (server-side).

This module validates the wizard JSON payload (as posted by the UI) before
it is transformed/persisted. It is intentionally defensive and supports
multiple payload shapes (legacy and nested "definition" structures).

Key features:
- Validates events against workflows.events.Events
- Validates steps against registered executors
- Validates webhook/email step params
- Validates templated strings compile (Django templates)
- Blocks known-invalid template tokens like `ctx.vars.*`
- Ensures every step has an id (failsafe for UI bugs)
- Enforces: a step may not reference future step outputs (ctx.steps.step_<k> where k >= idx)
- Validates transitions refer to existing step ids (when transitions are present)
- Enforces event-dependent allowed step types (e.g., disallow Approval for device actions)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from django.template import TemplateSyntaxError, engines
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
    """Return the set of registered step type identifiers."""
    return StepExecutorFactory.registered_types()


def _positive_int(value: Any) -> bool:
    try:
        return int(value) > 0
    except Exception:  # noqa: BLE001
        return False


# ---------------------- payload shape helpers ----------------------


def _get_definition(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the inner "definition" dict, supporting different shapes.

    Supported:
    - payload["definition"]["definition"] (export-like)
    - payload["definition"] (wizard-like)
    - payload (legacy flat)
    """
    d = payload.get('definition')
    if isinstance(d, dict) and isinstance(d.get('definition'), dict):
        return d['definition']
    return d if isinstance(d, dict) else payload


def _get_steps(payload: dict[str, Any]) -> list[Any]:
    d = _get_definition(payload)
    steps = d.get('steps')
    if isinstance(steps, list):
        return steps
    steps2 = payload.get('steps')
    return steps2 if isinstance(steps2, list) else []


def _get_events(payload: dict[str, Any]) -> list[Any]:
    d = _get_definition(payload)
    events = d.get('events')
    if isinstance(events, list):
        return events
    events2 = payload.get('events')
    return events2 if isinstance(events2, list) else []


def _get_transitions(payload: dict[str, Any]) -> list[Any]:
    d = _get_definition(payload)
    transitions = d.get('transitions')
    if isinstance(transitions, list):
        return transitions
    transitions2 = payload.get('transitions')
    return transitions2 if isinstance(transitions2, list) else []


def _get_primary_event(payload: dict[str, Any]) -> tuple[str, str, str]:
    """Return (handler, protocol_lc, operation_lc) from the first event, or ('','','')."""
    events = _get_events(payload)
    if not events or not isinstance(events[0], dict):
        return '', '', ''
    e0 = events[0]
    handler = str(e0.get('handler') or '').strip()
    protocol = str(e0.get('protocol') or '').strip().lower()
    operation = str(e0.get('operation') or '').strip().lower()
    return handler, protocol, operation


# ---------------------- templated-string validation ----------------------

_FORBIDDEN_TPL_SUBSTRINGS = (
    'ctx.vars.*',
    '{{ ctx.vars.* }}',
)


def _contains_forbidden_template_tokens(s: str) -> str | None:
    for bad in _FORBIDDEN_TPL_SUBSTRINGS:
        if bad in s:
            return bad
    return None


def _compile_django_template(src: str) -> str | None:
    """Compile a Django template string and return error message, else None."""
    dj = engines['django']
    try:
        dj.from_string(src)
    except TemplateSyntaxError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001
        return str(exc)
    return None


def _validate_templated_string(
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
        _error(errors, _('Step #%s (%s): %s must be a string if provided.') % (idx, step_type, field))
        return

    bad = _contains_forbidden_template_tokens(value)
    if bad:
        _error(
            errors,
            _(
                "Step #%s (%s): '%s' is not valid in templates. "
                "Use 'ctx.vars' (dict), a specific key like 'ctx.vars.response'."
            )
            % (idx, step_type, bad),
        )
        return

    msg = _compile_django_template(value)
    if msg:
        _error(errors, _('Step #%s (%s): template syntax error in %s: %s') % (idx, step_type, field, msg))


# ---------------------- no-future-step-refs validation ----------------------

_STEP_REF_RE = re.compile(r'\bctx\.steps\.step_(\d+)\b')


def _validate_no_future_step_refs(
    *,
    idx: int,
    step_type: str,
    field: str,
    value: Any,
    errors: list[str],
) -> None:
    """Disallow ctx.steps.step_<k> references where k >= idx inside step idx."""
    if not isinstance(value, str) or not value:
        return

    refs = {int(m.group(1)) for m in _STEP_REF_RE.finditer(value) if m.group(1).isdigit()}
    future = sorted(k for k in refs if k >= idx)
    if future:
        _error(
            errors,
            _(
                'Step #%s (%s): %s references a not yet executed step "%s". '
                'A step may only reference already executed steps.'
            )
            % (idx, step_type, field, ', '.join(f'step_{k}' for k in future)),
        )


# ---------------------- event-dependent allowed steps policy ----------------------

def _allowed_step_types_for_event(payload: dict[str, Any]) -> set[str] | None:
    """Return allowed step types for the current event, or None to allow all.

    Policy implemented now:
    - handler == "device_action": Approval steps are not allowed
    """
    registered = _registered_step_types()
    handler, protocol, operation = _get_primary_event(payload)  # noqa: F841  (reserved for future rules)

    if handler == 'device_action':
        # Only disallow Approval (as requested).
        # Keep everything else that is registered.
        return {t for t in registered if t != 'Approval'}

    # Default: allow all registered types
    return None


def _validate_step_types_allowed(payload: dict[str, Any], errors: list[str]) -> None:
    allowed = _allowed_step_types_for_event(payload)
    if allowed is None:
        return

    steps = _get_steps(payload)
    for i, s in enumerate(steps, start=1):
        if not isinstance(s, dict):
            continue
        st = s.get('type')
        if isinstance(st, str) and st and st not in allowed:
            handler, protocol, operation = _get_primary_event(payload)
            _error(
                errors,
                _(
                    'Step #%s: type "%s" is not allowed for event "%s" (protocol="%s", operation="%s").'
                )
                % (i, st, handler or '', protocol or '', operation or ''),
            )


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
    """Allow: status | text | json[.a.b.0] | headers[.x_y] (no dashes in dot lookups)."""
    if not isinstance(s, str) or not s:
        return False
    if s in {'status', 'text', 'json', 'headers'}:
        return True
    if s.startswith(('json.', 'headers.')):
        return _is_dotpath(s)
    return False


# ---------------------------- per step -----------------------------


def _validate_email_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    recips_raw = params.get('recipients', '')
    to: Sequence[str] = normalize_addresses(recips_raw)
    if not to:
        _error(errors, _('Step #%s (Email): at least one recipient is required.') % idx)

    _ = normalize_addresses(params.get('cc'))
    _ = normalize_addresses(params.get('bcc'))

    template = (params.get('template') or '').strip()
    subject = (params.get('subject') or '').strip()
    body = (params.get('body') or '').strip()

    if not template:
        if not subject:
            _error(errors, _('Step #%s (Email): subject is required in custom mode.') % idx)
        if not body:
            _error(errors, _('Step #%s (Email): body is required in custom mode.') % idx)

    if subject:
        _validate_templated_string(idx=idx, step_type='Email', field='subject', value=params.get('subject'), errors=errors)
        _validate_no_future_step_refs(idx=idx, step_type='Email', field='subject', value=params.get('subject'), errors=errors)
    if body:
        _validate_templated_string(idx=idx, step_type='Email', field='body', value=params.get('body'), errors=errors)
        _validate_no_future_step_refs(idx=idx, step_type='Email', field='body', value=params.get('body'), errors=errors)


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


def _validate_webhook_basic_fields(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    url = (params.get('url') or '').strip()
    if not _is_http_url(url):
        _error(errors, _('Step #%s (Webhook): url is required and must start with http:// or https://.') % idx)

    method = (params.get('method') or 'POST').upper()
    if method not in _ALLOWED_METHODS:
        _error(errors, _('Step #%s (Webhook): method must be one of %s.') % (idx, ', '.join(sorted(_ALLOWED_METHODS))))

    headers = params.get('headers')
    if headers is not None and not _validate_headers_dict(headers):
        _error(errors, _('Step #%s (Webhook): headers must be an object of string keys and string/number values.') % idx)

    body = params.get('body')
    if method == 'GET' and body not in (None, '', {}):
        _error(errors, _('Step #%s (Webhook): body is not allowed for GET requests.') % idx)
    elif body is not None and not isinstance(body, (str, Mapping, list)):
        _error(errors, _('Step #%s (Webhook): body must be a string, object, or array if provided.') % idx)

    if url:
        _validate_templated_string(idx=idx, step_type='Webhook', field='url', value=params.get('url'), errors=errors)
        _validate_no_future_step_refs(idx=idx, step_type='Webhook', field='url', value=params.get('url'), errors=errors)

    if isinstance(headers, Mapping):
        for hk, hv in headers.items():
            if isinstance(hv, str) and hv:
                _validate_templated_string(idx=idx, step_type='Webhook', field=f'headers.{hk}', value=hv, errors=errors)
                _validate_no_future_step_refs(idx=idx, step_type='Webhook', field=f'headers.{hk}', value=hv, errors=errors)

    if isinstance(body, str) and body.strip():
        _validate_templated_string(idx=idx, step_type='Webhook', field='body', value=body, errors=errors)
        _validate_no_future_step_refs(idx=idx, step_type='Webhook', field='body', value=body, errors=errors)


def _validate_webhook_auth_and_timeout(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    ok, msg = _validate_webhook_auth(params.get('auth'))
    if not ok:
        _error(errors, _('Step #%s (Webhook): %s') % (idx, msg or _('invalid auth')))

    tmo = params.get('timeoutSecs')
    if tmo is None:
        return

    try:
        tmo_i = int(tmo)
    except Exception:  # noqa: BLE001
        _error(errors, _('Step #%s (Webhook): timeoutSecs must be an integer (seconds).') % idx)
        return

    if not (1 <= tmo_i <= _WEBHOOK_MAX_TIMEOUT_SECS):
        _error(errors, _('Step #%s (Webhook): timeoutSecs must be between 1 and 120.') % idx)


def _validate_webhook_variable_mapping(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    webhook_variable = (params.get('webhook_variable') or '').strip()
    if webhook_variable and not _is_bare_var_path(webhook_variable):
        _error(
            errors,
            _("Step #%s (Webhook): webhook_variable must be a variable path like 'serial_number' or 'http.status'.") % idx,
        )

    result_source = (params.get('result_source') or 'auto').strip().lower()
    if result_source and result_source not in {'auto', 'json', 'text', 'status', 'headers'}:
        _error(errors, _('Step #%s (Webhook): result_source must be one of auto/json/text/status/headers.') % idx)

    if 'export' in params and 'exports' not in params:
        _error(
            errors,
            _(
                "Step #%s (Webhook): use 'exports': [ {'from_path':'json.foo','to_path':'my.foo'} ] "
                "instead of legacy 'export' mapping."
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
                    "Step #%s (Webhook): export #%s from_path must be one of "
                    "'status', 'text', 'json[.path]' or 'headers[.path]'."
                )
                % (idx, j),
            )

        if not _is_bare_var_path(tp):
            _error(
                errors,
                _(
                    "Step #%s (Webhook): export #%s to_path must be a variable path like "
                    "'serial_number' or 'http.status' (no 'vars.' prefix)."
                )
                % (idx, j),
            )
        elif tp in seen_to:
            _error(errors, _("Step #%s (Webhook): duplicate to_path '%s' in exports.") % (idx, tp))
        else:
            seen_to.add(tp)


def _validate_webhook_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    _validate_webhook_basic_fields(idx, params, errors)
    _validate_webhook_auth_and_timeout(idx, params, errors)
    _validate_webhook_variable_mapping(idx, params, errors)


# ---------------------------- top-level -----------------------------


def _validate_name(payload: dict[str, Any], errors: list[str]) -> None:
    name = payload.get('name')
    if not isinstance(name, str) or not name.strip():
        _error(errors, _('Name is required.'))


def _validate_events(payload: dict[str, Any], errors: list[str]) -> None:
    events = _get_events(payload)
    if not events:
        _error(errors, _('At least one event is required.'))
        return

    triples = _known_event_triples()
    for i, t in enumerate(events, start=1):
        if not isinstance(t, dict):
            _error(errors, _('Event #%s is not an object.') % i)
            continue

        handler = (t.get('handler') or '').strip()
        protocol = (t.get('protocol') or '').strip().lower()
        operation = (t.get('operation') or '').strip()

        if not handler:
            _error(errors, _('Event #%s: handler is required.') % i)
            continue

        needs_po = handler == 'certificate_request'
        if needs_po and (not protocol or not operation):
            _error(errors, _('Event #%s: protocol and operation are required for certificate_request.') % i)

        key = (handler, protocol, operation) if needs_po else (handler, protocol or '', operation or '')
        if key not in triples:
            _error(errors, _('Event #%s: unknown handler/protocol/operation combination.') % i)


def _ensure_step_ids(payload: dict[str, Any], errors: list[str]) -> None:
    """Ensure every step has an id. If missing, inject 'step-<n>'.

    This is a failsafe for UI bugs; it keeps the backend stable enough to validate.
    """
    steps = _get_steps(payload)
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
            _error(errors, _("Duplicate step id '%s'. Step ids must be unique.") % sid)
        seen.add(sid)


def _validate_single_step(idx: int, step: Any, registered: set[str], errors: list[str]) -> None:
    if not isinstance(step, dict):
        _error(errors, _('Step #%s is not an object.') % idx)
        return

    sid = step.get('id')
    if not isinstance(sid, str) or not sid.strip():
        _error(errors, _('Step #%s: id is required and must be a string.') % idx)

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


def _validate_steps(payload: dict[str, Any], errors: list[str]) -> None:
    steps = _get_steps(payload)
    if not steps:
        _error(errors, _('At least one step is required.'))
        return

    registered = _registered_step_types()
    for i, step in enumerate(steps, start=1):
        _validate_single_step(i, step, registered, errors)


def _validate_transitions(payload: dict[str, Any], errors: list[str]) -> None:
    transitions = _get_transitions(payload)
    if not transitions:
        return

    steps = _get_steps(payload)
    step_ids = {s.get('id') for s in steps if isinstance(s, dict) and isinstance(s.get('id'), str)}

    for i, t in enumerate(transitions, start=1):
        if not isinstance(t, dict):
            _error(errors, _('Transition #%s is not an object.') % i)
            continue

        frm = t.get('from')
        to = t.get('to')
        if frm not in step_ids:
            _error(errors, _("Transition #%s: from '%s' does not match any step id.") % (i, frm))
        if to not in step_ids:
            _error(errors, _("Transition #%s: to '%s' does not match any step id.") % (i, to))


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
        list[str]: A list of human-readable error messages. Empty if valid.
    """
    errors: list[str] = []

    # Make payload robust against UI missing step ids (mutates payload)
    _ensure_step_ids(payload, errors)

    _validate_name(payload, errors)
    _validate_events(payload, errors)

    # Event-dependent step policy (enforced server-side)
    _validate_step_types_allowed(payload, errors)

    _validate_steps(payload, errors)
    _validate_transitions(payload, errors)
    _validate_scopes(payload, errors)
    return errors
