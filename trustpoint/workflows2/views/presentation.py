"""Presentation helpers shared by the Workflow 2 monitoring views."""

from __future__ import annotations

import json
from typing import Any

from devices.models import DeviceModel
from pki.models.ca import CaModel
from pki.models.domain import DomainModel


def _json_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def pretty_json(obj: Any) -> str:
    """Render JSON in a stable, human-readable way for templates."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def status_badge_class(status: str | None) -> str:
    """Map a workflow status to the Bootstrap badge class used in templates."""
    value = (status or '').strip().lower()
    badge_by_group = {
        'text-bg-success': {'ok', 'success', 'succeeded', 'done', 'completed', 'approved'},
        'text-bg-danger': {'failed', 'error', 'rejected'},
        'text-bg-warning': {'awaiting', 'paused', 'pending', 'expired'},
        'text-bg-primary': {'running'},
        'text-bg-secondary': {'queued', 'no_match'},
        'text-bg-dark': {'cancelled', 'canceled'},
        'text-bg-info': {'stopped'},
    }
    for badge_class, statuses in badge_by_group.items():
        if value in statuses:
            return badge_class
    return 'text-bg-secondary'


def summarize_source(source_json: dict[str, Any] | None) -> str:
    """Return a compact one-line summary for a source scope object."""
    source = source_json if isinstance(source_json, dict) else {}
    if source.get('trustpoint'):
        return 'Trustpoint-wide trigger'

    parts: list[str] = []
    if source.get('ca_id') is not None:
        parts.append(f'CA {source["ca_id"]}')
    if source.get('domain_id') is not None:
        parts.append(f'Domain {source["domain_id"]}')
    if source.get('device_id'):
        parts.append(f'Device {source["device_id"]}')

    return ' · '.join(parts) if parts else 'No source scope metadata'


def compact_value(value: Any, *, max_length: int = 96) -> str:
    """Shorten a value for summary cards while preserving useful context."""
    if value is None:
        return '—'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    if len(text) <= max_length:
        return text
    return f'{text[: max_length - 1]}…'


def resolve_source_context(source_json: dict[str, Any] | None) -> dict[str, Any]:
    """Resolve source scope identifiers into human-readable labels."""
    source = _json_object(source_json)
    rows: list[dict[str, str]] = []

    rows.append(
        {
            'label': 'Origin',
            'value': 'Internal Trustpoint event' if source.get('trustpoint') else 'External request',
            'meta': '',
        }
    )

    ca_id = source.get('ca_id')
    if ca_id is not None:
        try:
            ca = CaModel.objects.filter(pk=ca_id).only('id', 'unique_name').first()
        except (TypeError, ValueError):
            ca = None
        ca_title = ca.unique_name if ca is not None else f'CA #{ca_id}'
        rows.append(
            {
                'label': 'Certificate authority',
                'value': ca_title,
                'meta': f'ID {ca_id}',
            }
        )

    domain_id = source.get('domain_id')
    if domain_id is not None:
        try:
            domain = DomainModel.objects.select_related('issuing_ca').filter(pk=domain_id).first()
        except (TypeError, ValueError):
            domain = None
        meta = f'ID {domain_id}'
        if domain is not None and domain.issuing_ca is not None:
            meta = f'{meta} · issuing CA {domain.issuing_ca.unique_name}'
        rows.append(
            {
                'label': 'Domain',
                'value': domain.unique_name if domain is not None else f'Domain #{domain_id}',
                'meta': meta,
            }
        )

    device_id = source.get('device_id')
    if device_id:
        try:
            device = DeviceModel.objects.select_related('domain').filter(pk=device_id).first()
        except (TypeError, ValueError):
            device = None
        meta_parts = [f'ID {device_id}']
        if device is not None and device.serial_number:
            meta_parts.append(f'S/N {device.serial_number}')
        if device is not None and device.domain is not None:
            meta_parts.append(f'Domain {device.domain.unique_name}')
        rows.append(
            {
                'label': 'Device',
                'value': device.common_name if device is not None else f'Device #{device_id}',
                'meta': ' · '.join(meta_parts),
            }
        )

    summary = rows[0]['value'] if len(rows) == 1 else ' · '.join(
        row['value'] for row in rows if row['label'] != 'Origin'
    ) or rows[0]['value']

    return {
        'summary': summary,
        'rows': rows,
    }


def describe_event_context(event_json: dict[str, Any] | None) -> list[dict[str, str]]:
    """Return friendly event metadata rows for run and instance detail views."""
    event = _json_object(event_json)
    rows: list[dict[str, str]] = []

    device = _json_object(event.get('device'))
    if device:
        device_title = device.get('common_name') or device.get('serial_number') or device.get('id')
        if device_title:
            rows.append({'label': 'Event device', 'value': str(device_title), 'meta': ''})
        if device.get('serial_number'):
            rows.append({'label': 'Serial number', 'value': str(device['serial_number']), 'meta': ''})
        domain_id = device.get('domain_id')
        if isinstance(domain_id, (str, int)):
            try:
                domain = DomainModel.objects.filter(pk=domain_id).only('unique_name').first()
            except (TypeError, ValueError):
                domain = None
            rows.append(
                {
                    'label': 'Device domain',
                    'value': domain.unique_name if domain is not None else f'Domain #{domain_id}',
                    'meta': '',
                }
            )

    _append_protocol_rows(rows, payload=_json_object(event.get('est')), protocol='EST')
    _append_protocol_rows(rows, payload=_json_object(event.get('rest')), protocol='REST')

    return rows


def _append_protocol_rows(
    rows: list[dict[str, str]],
    *,
    payload: dict[str, Any],
    protocol: str,
) -> None:
    """Append operation/profile rows for one protocol payload."""
    if not payload:
        return
    if payload.get('operation'):
        rows.append({'label': f'{protocol} operation', 'value': str(payload['operation']), 'meta': ''})
    if payload.get('cert_profile'):
        rows.append({'label': 'Certificate profile', 'value': str(payload['cert_profile']), 'meta': ''})


def summarize_named_values(values: dict[str, Any] | None, *, limit: int = 8) -> list[dict[str, str]]:
    """Return a compact summary of named values such as workflow vars."""
    if not isinstance(values, dict):
        return []
    return [
        {
            'label': str(name),
            'value': compact_value(values.get(name)),
            'meta': '',
        }
        for name in sorted(values.keys())[:limit]
    ]


def build_step_meta_from_ir(ir_json: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    """Build a map of step identifiers to display metadata from compiled IR."""
    ir = _json_object(ir_json)
    workflow = _json_object(ir.get('workflow'))
    steps = _json_object(workflow.get('steps'))

    meta: dict[str, dict[str, str]] = {}
    for step_id, step_value in steps.items():
        step = _json_object(step_value)
        if not step:
            continue
        params = _json_object(step.get('params'))
        meta[str(step_id)] = {
            'id': str(step_id),
            'type': str(step.get('type') or ''),
            'title': str(step.get('title') or params.get('title') or step_id),
            'description': str(step.get('description') or params.get('description') or ''),
        }
    return meta


def describe_step(step_id: str | None, step_meta: dict[str, dict[str, str]]) -> dict[str, str] | None:
    """Return the display metadata for one step identifier."""
    if not step_id:
        return None

    meta = step_meta.get(step_id) or {}
    return {
        'id': step_id,
        'title': meta.get('title') or step_id,
        'type': meta.get('type') or '',
        'description': meta.get('description') or '',
    }
