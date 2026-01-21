"""Shared helpers for wizard payload validators."""

from __future__ import annotations

from typing import Any, cast

from workflows.events import Events
from workflows.services.executors.factory import StepExecutorFactory

_SEGMENT_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.')


def error(errors: list[str], msg: str) -> None:
    """Append a validation error message."""
    errors.append(msg)


def is_dotpath(s: str) -> bool:
    """Return True if `s` is a valid dot-path like 'serial_number' or 'http.status'."""
    if not isinstance(s, str) or not s:
        return False
    if any(ch not in _SEGMENT_CHARS for ch in s):
        return False
    parts = s.split('.')
    return all(p and (p[0].isalpha() or p[0] == '_') and p.replace('_', '').isalnum() for p in parts)


def is_bare_var_path(s: str) -> bool:
    """Bare variable path (no 'vars.'), at least one segment, dot-separated."""
    return is_dotpath(s)


def is_http_url(s: str) -> bool:
    """Return True if string starts with http:// or https://."""
    return isinstance(s, str) and s.strip().lower().startswith(('http://', 'https://'))


def known_event_triples() -> set[tuple[str, str, str]]:
    """Return set of (handler, protocol_lc, operation) from Events."""
    triples: set[tuple[str, str, str]] = set()
    for t in Events.all():
        h = (t.handler or '').strip()
        p = (t.protocol or '').strip().lower()
        o = (t.operation or '').strip()
        triples.add((h, p, o))
        if not p and not o:
            triples.add((h, '', ''))
    return triples


def registered_step_types() -> set[str]:
    """Return the set of registered step type identifiers."""
    return StepExecutorFactory.registered_types()


def positive_int(value: Any) -> bool:
    """Return True if value can be parsed as int and is > 0."""
    try:
        return int(value) > 0
    except Exception:  # noqa: BLE001
        return False


def safe_step_key(raw_id: str) -> str:
    """Match build_context() safe key behavior for ctx.steps keys.

    - Replace any char not [A-Za-z0-9_] with '_'
    - Ensure first char is alpha or '_'
    """
    if not raw_id:
        return 'step'
    out_chars: list[str] = []
    for ch in raw_id:
        out_chars.append(ch if (ch.isalnum() or ch == '_') else '_')
    safe = ''.join(out_chars)
    if not (safe[0].isalpha() or safe[0] == '_'):
        safe = f's_{safe}'
    return safe


def get_definition(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the inner 'definition' dict, supporting different shapes."""
    d = payload.get('definition')
    if isinstance(d, dict) and isinstance(d.get('definition'), dict):
        return cast('dict[str, Any]', d['definition'])
    return d if isinstance(d, dict) else payload


def get_steps(payload: dict[str, Any]) -> list[Any]:
    """Return steps list from supported payload shapes."""
    d = get_definition(payload)
    steps = d.get('steps')
    if isinstance(steps, list):
        return steps
    steps2 = payload.get('steps')
    return steps2 if isinstance(steps2, list) else []


def get_events(payload: dict[str, Any]) -> list[Any]:
    """Return events list from supported payload shapes."""
    d = get_definition(payload)
    events = d.get('events')
    if isinstance(events, list):
        return events
    events2 = payload.get('events')
    return events2 if isinstance(events2, list) else []


def get_transitions(payload: dict[str, Any]) -> list[Any]:
    """Return transitions list from supported payload shapes."""
    d = get_definition(payload)
    transitions = d.get('transitions')
    if isinstance(transitions, list):
        return transitions
    transitions2 = payload.get('transitions')
    return transitions2 if isinstance(transitions2, list) else []


def get_primary_event(payload: dict[str, Any]) -> tuple[str, str, str]:
    """Return (handler, protocol_lc, operation_lc) from first event, or ('','','')."""
    events = get_events(payload)
    if not events or not isinstance(events[0], dict):
        return '', '', ''
    e0 = events[0]
    handler = str(e0.get('handler') or '').strip()
    protocol = str(e0.get('protocol') or '').strip().lower()
    operation = str(e0.get('operation') or '').strip().lower()
    return handler, protocol, operation


def step_key_order_map(payload: dict[str, Any]) -> dict[str, int]:
    """Map ctx.steps.<safe_key> to the 1-based step order index."""
    out: dict[str, int] = {}
    for i, s in enumerate(get_steps(payload), start=1):
        if not isinstance(s, dict):
            continue
        sid = s.get('id')
        if isinstance(sid, str) and sid.strip():
            out[safe_step_key(sid)] = i
    return out
