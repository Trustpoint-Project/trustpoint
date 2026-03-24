from __future__ import annotations

import json
from typing import Any

from devices.models import DeviceModel
from pki.models.ca import CaModel
from pki.models.domain import DomainModel


def pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def status_badge_class(status: str | None) -> str:
    value = (status or '').strip().lower()
    if value in {'ok', 'success', 'succeeded', 'done', 'completed', 'approved'}:
        return 'text-bg-success'
    if value in {'failed', 'error', 'rejected'}:
        return 'text-bg-danger'
    if value in {'awaiting', 'paused', 'pending', 'expired'}:
        return 'text-bg-warning'
    if value in {'running'}:
        return 'text-bg-primary'
    if value in {'queued', 'no_match'}:
        return 'text-bg-secondary'
    if value in {'cancelled', 'canceled'}:
        return 'text-bg-dark'
    if value in {'stopped'}:
        return 'text-bg-info'
    return 'text-bg-secondary'


def summarize_source(source_json: dict[str, Any] | None) -> str:
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
    if value is None:
        return '—'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    if len(text) <= max_length:
        return text
    return f'{text[: max_length - 1]}…'


def resolve_source_context(source_json: dict[str, Any] | None) -> dict[str, Any]:
    source = source_json if isinstance(source_json, dict) else {}
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
        rows.append(
            {
                'label': 'Certificate authority',
                'value': ca.unique_name if ca else f'CA #{ca_id}',
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
        if domain and domain.issuing_ca_id:
            meta = f'{meta} · issuing CA {domain.issuing_ca.unique_name}'
        rows.append(
            {
                'label': 'Domain',
                'value': domain.unique_name if domain else f'Domain #{domain_id}',
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
        if device and device.serial_number:
            meta_parts.append(f'S/N {device.serial_number}')
        if device and device.domain_id:
            meta_parts.append(f'Domain {device.domain.unique_name}')
        rows.append(
            {
                'label': 'Device',
                'value': device.common_name if device else f'Device #{device_id}',
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
    event = event_json if isinstance(event_json, dict) else {}
    rows: list[dict[str, str]] = []

    device = event.get('device')
    if isinstance(device, dict):
        device_title = device.get('common_name') or device.get('serial_number') or device.get('id')
        if device_title:
            rows.append({'label': 'Event device', 'value': str(device_title), 'meta': ''})
        if device.get('serial_number'):
            rows.append({'label': 'Serial number', 'value': str(device['serial_number']), 'meta': ''})
        if device.get('domain_id') is not None:
            try:
                domain = DomainModel.objects.filter(pk=device.get('domain_id')).only('unique_name').first()
            except (TypeError, ValueError):
                domain = None
            rows.append(
                {
                    'label': 'Device domain',
                    'value': domain.unique_name if domain else f'Domain #{device["domain_id"]}',
                    'meta': '',
                }
            )

    est = event.get('est')
    if isinstance(est, dict):
        if est.get('operation'):
            rows.append({'label': 'EST operation', 'value': str(est['operation']), 'meta': ''})
        if est.get('cert_profile'):
            rows.append({'label': 'Certificate profile', 'value': str(est['cert_profile']), 'meta': ''})

    return rows


def summarize_named_values(values: dict[str, Any] | None, *, limit: int = 8) -> list[dict[str, str]]:
    if not isinstance(values, dict):
        return []

    rows: list[dict[str, str]] = []
    for name in sorted(values.keys())[:limit]:
        rows.append(
            {
                'label': str(name),
                'value': compact_value(values.get(name)),
                'meta': '',
            }
        )
    return rows


def build_step_meta_from_ir(ir_json: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    ir = ir_json if isinstance(ir_json, dict) else {}
    workflow = ir.get('workflow') if isinstance(ir.get('workflow'), dict) else {}
    steps = workflow.get('steps') if isinstance(workflow.get('steps'), dict) else {}

    meta: dict[str, dict[str, str]] = {}
    for step_id, step in steps.items():
        if not isinstance(step, dict):
            continue
        params = step.get('params') if isinstance(step.get('params'), dict) else {}
        meta[str(step_id)] = {
            'id': str(step_id),
            'type': str(step.get('type') or ''),
            'title': str(step.get('title') or params.get('title') or step_id),
            'description': str(step.get('description') or params.get('description') or ''),
        }
    return meta


def describe_step(step_id: str | None, step_meta: dict[str, dict[str, str]]) -> dict[str, str] | None:
    if not step_id:
        return None

    meta = step_meta.get(step_id) or {}
    return {
        'id': step_id,
        'title': meta.get('title') or step_id,
        'type': meta.get('type') or '',
        'description': meta.get('description') or '',
    }
