"""Presentation helpers shared by the Workflow 2 monitoring views."""

from __future__ import annotations

import json
from typing import Any

from django.urls import NoReverseMatch, reverse
from django.utils.translation import gettext as _

from devices.models import DeviceModel
from pki.models.ca import CaModel
from pki.models.domain import DomainModel


def _json_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_reverse(name: str, **kwargs: Any) -> str | None:
    """Return a reversed URL or ``None`` when the target cannot be resolved."""
    try:
        return reverse(name, kwargs=kwargs)
    except NoReverseMatch:
        return None


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
        'text-bg-secondary': {'queued'},
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
        return _('Trustpoint-wide trigger')

    parts: list[str] = []
    if source.get('ca_id') is not None:
        parts.append(_('CA %(id)s') % {'id': source['ca_id']})
    if source.get('domain_id') is not None:
        parts.append(_('Domain %(id)s') % {'id': source['domain_id']})
    if source.get('device_id'):
        parts.append(_('Device %(id)s') % {'id': source['device_id']})

    return ' · '.join(parts) if parts else _('No source scope metadata')


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
    rows: list[dict[str, str | None]] = []

    rows.append(
        {
            'label': _('Origin'),
            'value': _('Internal Trustpoint event') if source.get('trustpoint') else _('External request'),
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
                'label': _('Certificate authority'),
                'value': ca_title,
                'meta': f'ID {ca_id}',
                'url': _safe_reverse('pki:issuing_cas-detail', pk=ca_id),
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
                'label': _('Domain'),
                'value': domain.unique_name if domain is not None else _('Domain #%(id)s') % {'id': domain_id},
                'meta': meta,
                'url': _safe_reverse('pki:domains-detail', pk=domain_id),
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
            meta_parts.append(_('Domain %(name)s') % {'name': device.domain.unique_name})
        rows.append(
            {
                'label': _('Device'),
                'value': device.common_name if device is not None else _('Device #%(id)s') % {'id': device_id},
                'meta': ' · '.join(meta_parts),
                'url': _safe_reverse('devices:devices_certificate_lifecycle_management', pk=device_id),
            }
        )

    summary_parts = [row['value'] for row in rows if row['label'] != 'Origin' and row['value'] is not None]
    summary = rows[0]['value'] if len(rows) == 1 else ' · '.join(summary_parts) or rows[0]['value']

    return {
        'summary': summary,
        'rows': rows,
    }


def describe_event_context(event_json: dict[str, Any] | None) -> list[dict[str, str | None]]:
    """Return friendly event metadata rows for run and instance detail views."""
    event = _json_object(event_json)
    rows: list[dict[str, str | None]] = []

    _append_device_rows(rows, device=_json_object(event.get('device')))
    _append_certificate_rows(rows, certificate=_json_object(event.get('certificate')))

    _append_protocol_rows(rows, payload=_json_object(event.get('est')), protocol='EST')
    _append_protocol_rows(rows, payload=_json_object(event.get('rest')), protocol='REST')

    return rows


def _append_device_rows(rows: list[dict[str, str | None]], *, device: dict[str, Any]) -> None:
    """Append human-readable rows for device event payloads."""
    if not device:
        return

    device_title = device.get('common_name') or device.get('serial_number') or device.get('id')
    device_id = device.get('id')
    if device_title:
        rows.append(
            {
                'label': _('Event device'),
                'value': str(device_title),
                'meta': '',
                'url': (
                    _safe_reverse('devices:devices_certificate_lifecycle_management', pk=device_id)
                    if device_id
                    else None
                ),
            }
        )
    if device.get('serial_number'):
        rows.append(
            {'label': _('Serial number'), 'value': str(device['serial_number']), 'meta': '', 'url': None}
        )
    domain_id = device.get('domain_id')
    if isinstance(domain_id, (str, int)):
        try:
            domain = DomainModel.objects.filter(pk=domain_id).only('unique_name').first()
        except (TypeError, ValueError):
            domain = None
        rows.append(
            {
                'label': _('Device domain'),
                'value': domain.unique_name if domain is not None else _('Domain #%(id)s') % {'id': domain_id},
                'meta': '',
                'url': _safe_reverse('pki:domains-detail', pk=domain_id),
            }
        )
    changes = _json_object(device.get('changes'))
    if changes:
        rows.append(
            {
                'label': _('Changed fields'),
                'value': ', '.join(sorted(changes.keys())),
                'meta': '',
                'url': None,
            }
        )


def _append_certificate_rows(rows: list[dict[str, str | None]], *, certificate: dict[str, Any]) -> None:
    """Append human-readable rows for certificate lifecycle payloads."""
    if not certificate:
        return

    certificate_title = (
        certificate.get('common_name')
        or certificate.get('serial_number')
        or certificate.get('sha256_fingerprint')
        or certificate.get('id')
    )
    certificate_id = certificate.get('id')
    if certificate_title:
        rows.append(
            {
                'label': _('Certificate'),
                'value': str(certificate_title),
                'meta': '',
                'url': _safe_reverse('pki:certificate-detail', pk=certificate_id) if certificate_id else None,
            }
        )
    if certificate.get('serial_number'):
        rows.append(
            {
                'label': _('Certificate serial'),
                'value': str(certificate['serial_number']),
                'meta': '',
                'url': None,
            }
        )
    if certificate.get('cert_profile'):
        rows.append(
            {
                'label': _('Certificate profile'),
                'value': str(certificate['cert_profile']),
                'meta': '',
                'url': None,
            }
        )
    if certificate.get('revocation_reason'):
        rows.append(
            {'label': _('Revocation reason'), 'value': str(certificate['revocation_reason']), 'meta': '', 'url': None}
        )


def _append_protocol_rows(
    rows: list[dict[str, str | None]],
    *,
    payload: dict[str, Any],
    protocol: str,
) -> None:
    """Append operation/profile rows for one protocol payload."""
    if not payload:
        return
    if payload.get('operation'):
        rows.append(
            {
                'label': _('%(protocol)s operation') % {'protocol': protocol},
                'value': str(payload['operation']),
                'meta': '',
                'url': None,
            }
        )
    if payload.get('cert_profile'):
        rows.append({'label': _('Certificate profile'), 'value': str(payload['cert_profile']), 'meta': '', 'url': None})


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
