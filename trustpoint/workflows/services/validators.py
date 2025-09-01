# workflows/services/validators.py
from __future__ import annotations

from typing import Any

from django.utils.translation import gettext as _
from util.email import normalize_addresses

from workflows.services.executors.factory import NodeExecutorFactory
from workflows.triggers import Triggers


def _known_trigger_triples() -> set[tuple[str, str, str]]:
    triples: set[tuple[str, str, str]] = set()
    for t in Triggers.all():
        # Some triggers (like device_created) may have empty protocol/operation;
        # still include their (handler, '', '') triple.
        triples.add((t.handler, t.protocol or '', t.operation or ''))
    return triples


def _error(errors: list[str], msg: str) -> None:
    errors.append(msg)


def validate_wizard_payload(payload: dict[str, Any]) -> list[str]:
    """Validate the wizard JSON (pre-transform). Returns list of error messages."""
    errors: list[str] = []

    # --- name ---
    name = payload.get('name')
    if not isinstance(name, str) or not name.strip():
        _error(errors, _('Name is required.'))

    # --- triggers ---
    triggers = payload.get('triggers')
    if not isinstance(triggers, list) or not triggers:
        _error(errors, _('At least one trigger is required.'))
    else:
        triples = _known_trigger_triples()
        for i, t in enumerate(triggers, start=1):
            if not isinstance(t, dict):
                _error(errors, _(f'Trigger #{i} is not an object.'))
                continue
            handler = (t.get('handler') or '').strip()
            protocol = (t.get('protocol') or '').strip()
            operation = (t.get('operation') or '').strip()

            if not handler:
                _error(errors, _(f'Trigger #{i}: handler is required.'))
                continue

            # certificate_request requires protocol+operation;
            # other handlers may allow both empty.
            needs_po = handler == 'certificate_request'
            if needs_po and (not protocol or not operation):
                _error(errors, _(f'Trigger #{i}: protocol and operation are required for certificate_request.'))
            # ensure the triple exists in registry
            key = (handler, protocol, operation) if needs_po else (handler, protocol or '', operation or '')
            if key not in triples:
                _error(errors, _(f'Trigger #{i}: unknown handler/protocol/operation combination.'))

    # --- steps ---
    steps = payload.get('steps')
    if not isinstance(steps, list) or not steps:
        _error(errors, _('At least one step is required.'))
    else:
        registered = NodeExecutorFactory.registered_types()
        for i, s in enumerate(steps, start=1):
            if not isinstance(s, dict):
                _error(errors, _(f'Step #{i} is not an object.'))
                continue
            stype = s.get('type')
            if stype not in registered:
                _error(errors, _(f'Step #{i}: unknown type "{stype}".'))
                continue
            params = s.get('params') or {}
            if stype == 'Email':
                _validate_email_step(i, params, errors)

    # --- scopes ---
    scopes = payload.get('scopes')
    if isinstance(scopes, dict):
        total = sum(len(scopes.get(k, [])) for k in ('ca_ids', 'domain_ids', 'device_ids'))
        if total == 0:
            _error(errors, _('At least one scope (CA/Domain/Device) is required.'))
    elif isinstance(scopes, list):
        if not scopes:
            _error(errors, _('At least one scope (CA/Domain/Device) is required.'))
    else:
        _error(errors, _('Invalid scopes format.'))

    return errors


def _validate_email_step(idx: int, params: dict[str, Any], errors: list[str]) -> None:
    recips_raw = params.get('recipients', '')
    to = normalize_addresses(recips_raw)
    if not to:
        _error(errors, _(f'Step #{idx} (Email): at least one recipient is required.'))

    template = (params.get('template') or '').strip()
    subject = (params.get('subject') or '').strip()
    body = (params.get('body') or '').strip()

    if template:
        # templated mode → OK, no subject/body required
        return
    # custom mode → subject+body required
    if not subject:
        _error(errors, _(f'Step #{idx} (Email): subject is required in custom mode.'))
    if not body:
        _error(errors, _(f'Step #{idx} (Email): body is required in custom mode.'))
