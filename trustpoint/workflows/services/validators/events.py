"""Validation for workflow events."""

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _

from workflows.services.validators.common import error, get_events, known_event_triples


def validate_events(payload: dict[str, Any], errors: list[str]) -> None:
    """Validate that events exist and match known supported Events."""
    events = get_events(payload)
    if not events:
        error(errors, _('At least one event is required.'))
        return

    triples = known_event_triples()
    for i, t in enumerate(events, start=1):
        if not isinstance(t, dict):
            error(errors, _('Event #%s is not an object.') % i)
            continue

        handler = (t.get('handler') or '').strip()
        protocol = (t.get('protocol') or '').strip().lower()
        operation = (t.get('operation') or '').strip()

        if not handler:
            error(errors, _('Event #%s: handler is required.') % i)
            continue

        needs_po = handler == 'certificate_request'
        if needs_po and (not protocol or not operation):
            error(errors, _('Event #%s: protocol and operation are required for certificate_request.') % i)

        key = (handler, protocol, operation) if needs_po else (handler, protocol or '', operation or '')
        if key not in triples:
            error(errors, _('Event #%s: unknown handler/protocol/operation combination.') % i)
