"""Reusable context variable groups for built-in Workflow 2 triggers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils.translation import gettext_lazy as _

from workflows2.events.context import ContextVar

if TYPE_CHECKING:
    from collections.abc import Iterable


def ctx(*items: ContextVar) -> tuple[ContextVar, ...]:
    """Return the given context variables as a tuple."""
    return tuple(items)


def merge(*groups: Iterable[ContextVar]) -> tuple[ContextVar, ...]:
    """Merge context groups into one tuple while preserving the first occurrence.

    First occurrence wins.
    """
    out: list[ContextVar] = []
    seen: set[str] = set()

    for g in groups:
        for v in g:
            p = (v.path or '').strip()
            if not p or p in seen:
                continue
            seen.add(p)
            out.append(v)

    return tuple(out)


# --------------------------
# Common subsets
# --------------------------

DEVICE_CONTEXT = ctx(
    ContextVar(
        'event.device.id',
        'int',
        _('Device database ID.'),
        title=_('Device ID'),
        group='event.device',
        example=38,
    ),
    ContextVar(
        'event.device.uuid',
        'uuid',
        _('Device UUID.'),
        title=_('Device UUID'),
        group='event.device',
        example='550e8400-e29b-41d4-a716-446655440000',
    ),
    ContextVar(
        'event.device.common_name',
        'string',
        _('Device common name.'),
        title=_('Common name'),
        group='event.device',
        example='device-01.example.local',
    ),
    ContextVar(
        'event.device.serial_number',
        'string',
        _('Device serial number.'),
        title=_('Serial number'),
        group='event.device',
        example='ABC123456',
    ),
    ContextVar(
        'event.device.domain_id',
        'int',
        _('Domain ID of the device.'),
        title=_('Domain ID'),
        group='event.device',
        example=42,
    ),
)

DEVICE_UPDATE_CONTEXT = ctx(
    ContextVar(
        'event.device.before',
        'object',
        _('Tracked device values before the update.'),
        title=_('Device before'),
        group='event.device',
        example={'common_name': 'device-01', 'domain_id': 41},
    ),
    ContextVar(
        'event.device.after',
        'object',
        _('Tracked device values after the update.'),
        title=_('Device after'),
        group='event.device',
        example={'common_name': 'device-01', 'domain_id': 42},
    ),
    ContextVar(
        'event.device.changes',
        'object',
        _('Field-by-field changes emitted for the update.'),
        title=_('Device changes'),
        group='event.device',
        example={'domain_id': {'before': 41, 'after': 42}},
    ),
    ContextVar(
        'event.device.before.domain_id',
        'int',
        _('Previous device domain ID before the update.'),
        title=_('Previous domain ID'),
        group='event.device',
        example=41,
    ),
    ContextVar(
        'event.device.after.domain_id',
        'int',
        _('Device domain ID after the update.'),
        title=_('Updated domain ID'),
        group='event.device',
        example=42,
    ),
    ContextVar(
        'event.device.changes.domain_id.before',
        'int',
        _('Previous domain ID for a domain change.'),
        title=_('Changed domain before'),
        group='event.device',
        example=41,
    ),
    ContextVar(
        'event.device.changes.domain_id.after',
        'int',
        _('New domain ID for a domain change.'),
        title=_('Changed domain after'),
        group='event.device',
        example=42,
    ),
)

CERTIFICATE_CONTEXT = ctx(
    ContextVar(
        'event.certificate.id',
        'int',
        _('Certificate database ID.'),
        title=_('Certificate ID'),
        group='event.certificate',
        example=101,
    ),
    ContextVar(
        'event.certificate.common_name',
        'string',
        _('Certificate common name.'),
        title=_('Common name'),
        group='event.certificate',
        example='device-01.example.local',
    ),
    ContextVar(
        'event.certificate.serial_number',
        'string',
        _('Certificate serial number.'),
        title=_('Serial number'),
        group='event.certificate',
        example='04D2A6FF',
    ),
    ContextVar(
        'event.certificate.sha256_fingerprint',
        'string',
        _('Certificate SHA-256 fingerprint.'),
        title=_('Fingerprint'),
        group='event.certificate',
        example='A1B2C3D4...',
    ),
    ContextVar(
        'event.certificate.status',
        'string',
        _('Certificate status at the time of the event.'),
        title=_('Certificate status'),
        group='event.certificate',
        example='OK',
    ),
    ContextVar(
        'event.certificate.not_valid_before',
        'string',
        _('Certificate validity start time in ISO 8601 format.'),
        title=_('Valid from'),
        group='event.certificate',
        example='2026-03-26T10:00:00+00:00',
    ),
    ContextVar(
        'event.certificate.not_valid_after',
        'string',
        _('Certificate validity end time in ISO 8601 format.'),
        title=_('Valid until'),
        group='event.certificate',
        example='2027-03-26T10:00:00+00:00',
    ),
    ContextVar(
        'event.certificate.cert_profile',
        'string',
        _('Certificate profile used for issuance when available.'),
        title=_('Certificate profile'),
        group='event.certificate',
        example='TLS Client',
    ),
    ContextVar(
        'event.certificate.issued_credential_type',
        'string',
        _('Issued credential type when the certificate belongs to an issued credential.'),
        title=_('Issued credential type'),
        group='event.certificate',
        example='application_credential',
    ),
    ContextVar(
        'event.certificate.revocation_reason',
        'string',
        _('Revocation reason when the certificate was revoked.'),
        title=_('Revocation reason'),
        group='event.certificate',
        example='cessationOfOperation',
    ),
)

EST_CONTEXT = ctx(
    ContextVar(
        'event.est.operation',
        'string',
        _('EST operation name.'),
        title=_('EST operation'),
        group='event.est',
        example='simpleenroll',
    ),
    ContextVar(
        'event.est.fingerprint',
        'string',
        _('CSR fingerprint (SHA-256).'),
        title=_('CSR fingerprint'),
        group='event.est',
        example='0f2d7d8a...',
    ),
    ContextVar(
        'event.est.cert_profile',
        'string',
        _('Requested certificate profile.'),
        title=_('Certificate profile'),
        group='event.est',
        example='tls-client',
    ),
    ContextVar(
        'event.est.csr_pem',
        'string',
        _('CSR PEM payload.'),
        title=_('CSR PEM'),
        group='event.est',
    ),
)

REST_CONTEXT = ctx(
    ContextVar(
        'event.rest.operation',
        'string',
        _('REST enrollment operation name.'),
        title=_('REST operation'),
        group='event.rest',
        example='enroll',
    ),
    ContextVar(
        'event.rest.fingerprint',
        'string',
        _('CSR fingerprint (SHA-256).'),
        title=_('CSR fingerprint'),
        group='event.rest',
        example='0f2d7d8a...',
    ),
    ContextVar(
        'event.rest.cert_profile',
        'string',
        _('Requested certificate profile.'),
        title=_('Certificate profile'),
        group='event.rest',
        example='tls-client',
    ),
    ContextVar(
        'event.rest.csr_pem',
        'string',
        _('CSR PEM payload.'),
        title=_('CSR PEM'),
        group='event.rest',
    ),
)

CMP_CONTEXT = ctx(
    ContextVar(
        'event.cmp.operation',
        'string',
        _('CMP operation name.'),
        title=_('CMP operation'),
        group='event.cmp',
        example='initialization',
    ),
    ContextVar(
        'event.cmp.fingerprint',
        'string',
        _('CMP request fingerprint (SHA-256 over the raw request body).'),
        title=_('Request fingerprint'),
        group='event.cmp',
        example='0f2d7d8a...',
    ),
)

CMP_CERTREQ_CONTEXT = ctx(
        ContextVar(
        'event.cmp.cert_profile',
        'string',
        _('Requested certificate profile.'),
        title=_('Certificate profile'),
        group='event.cmp',
        example='tls-client',
    ),
)

CMP_CERTCONF_CONTEXT = ctx(
        ContextVar(
        'event.cmp.certconf_status',
        'string',
        _('CMP certConf status.'),
        title=_('certConf status'),
        group='event.cmp',
        example='accepted',
    ),
)

SOURCE_CONTEXT = ctx(
    ContextVar(
        'event.source.trustpoint',
        'bool',
        _('Event emitted trustpoint-wide.'),
        title=_('Trustpoint-wide'),
        group='event.source',
        example=True,
    ),
    ContextVar(
        'event.source.ca_id',
        'int',
        _('CA id if present.'),
        title=_('CA ID'),
        group='event.source',
        example=7,
    ),
    ContextVar(
        'event.source.domain_id',
        'int',
        _('Domain id if present.'),
        title=_('Domain ID'),
        group='event.source',
        example=42,
    ),
    ContextVar(
        'event.source.device_id',
        'string',
        _('Device id if present.'),
        title=_('Device ID'),
        group='event.source',
        example='550e8400-e29b-41d4-a716-446655440000',
    ),
)
