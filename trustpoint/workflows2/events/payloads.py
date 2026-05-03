"""Helpers for building JSON-safe Workflow 2 event payloads."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pki.models.certificate import CertificateModel


DEVICE_TRACKED_FIELDS: tuple[str, ...] = (
    'common_name',
    'serial_number',
    'domain_id',
    'ip_address',
    'opc_server_port',
    'device_type',
    'onboarding_config_id',
    'no_onboarding_config_id',
    'opc_gds_push_enable_periodic_update',
    'opc_gds_push_renewal_interval',
)


def _json_scalar(value: Any) -> str | int | float | bool | None:
    """Return a JSON-safe scalar value or ``None`` for unsupported objects."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return None


def _isoformat_or_none(value: Any) -> str | None:
    """Return an ISO 8601 string for datetimes and ``None`` otherwise."""
    if isinstance(value, datetime):
        return value.isoformat()
    return None


def serialize_source(source: Any) -> dict[str, Any]:
    """Serialize an event source object into plain JSON-compatible data."""
    return {
        'trustpoint': bool(getattr(source, 'trustpoint', False)),
        'ca_id': _json_scalar(getattr(source, 'ca_id', None)),
        'domain_id': _json_scalar(getattr(source, 'domain_id', None)),
        'device_id': str(device_id) if (device_id := getattr(source, 'device_id', None)) is not None else None,
    }


def build_device_snapshot(device: Any) -> dict[str, Any]:
    """Return a stable JSON-safe snapshot of tracked device fields."""
    snapshot: dict[str, Any] = {
        'id': str(device_id) if (device_id := getattr(device, 'id', None)) is not None else None,
    }
    for field_name in DEVICE_TRACKED_FIELDS:
        snapshot[field_name] = _json_scalar(getattr(device, field_name, None))
    return snapshot


def build_device_changes(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Return a field-by-field change set between two device snapshots."""
    before_map = before or {}
    after_map = after or {}
    changes: dict[str, dict[str, Any]] = {}

    for field_name in DEVICE_TRACKED_FIELDS:
        before_value = before_map.get(field_name)
        after_value = after_map.get(field_name)
        if before_value == after_value:
            continue
        changes[field_name] = {
            'before': before_value,
            'after': after_value,
        }

    return changes


def build_certificate_snapshot(
    certificate: CertificateModel,
    *,
    cert_profile: str | None = None,
    issued_credential_type: str | None = None,
    revocation_reason: str | None = None,
) -> dict[str, Any]:
    """Return a JSON-safe snapshot for certificate lifecycle triggers."""
    payload = {
        'id': certificate.pk,
        'common_name': certificate.common_name or '',
        'serial_number': certificate.serial_number or '',
        'sha256_fingerprint': certificate.sha256_fingerprint or '',
        'status': str(certificate.certificate_status),
        'not_valid_before': _isoformat_or_none(certificate.not_valid_before),
        'not_valid_after': _isoformat_or_none(certificate.not_valid_after),
    }
    if cert_profile:
        payload['cert_profile'] = cert_profile
    if issued_credential_type:
        payload['issued_credential_type'] = issued_credential_type
    if revocation_reason:
        payload['revocation_reason'] = revocation_reason
    return payload
