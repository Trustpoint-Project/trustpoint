"""Reusable context variable groups for built-in Workflow 2 triggers."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
        'uuid',
        'Device UUID.',
        title='Device ID',
        group='event.device',
        example='550e8400-e29b-41d4-a716-446655440000',
    ),
    ContextVar(
        'event.device.common_name',
        'string',
        'Device common name.',
        title='Common name',
        group='event.device',
        example='device-01.example.local',
    ),
    ContextVar(
        'event.device.serial_number',
        'string',
        'Device serial number.',
        title='Serial number',
        group='event.device',
        example='ABC123456',
    ),
    ContextVar(
        'event.device.domain_id',
        'int',
        'Domain ID of the device.',
        title='Domain ID',
        group='event.device',
        example=42,
    ),
)

DEVICE_DOMAIN_CHANGE_CONTEXT = ctx(
    ContextVar(
        'event.device.old_domain_id',
        'int',
        'Previous domain ID before the device was moved.',
        title='Previous domain ID',
        group='event.device',
        example=41,
    ),
    ContextVar(
        'event.device.new_domain_id',
        'int',
        'New domain ID after the device was moved.',
        title='New domain ID',
        group='event.device',
        example=42,
    ),
)

EST_CONTEXT = ctx(
    ContextVar(
        'event.est.operation',
        'string',
        'EST operation name.',
        title='EST operation',
        group='event.est',
        example='simpleenroll',
    ),
    ContextVar(
        'event.est.fingerprint',
        'string',
        'CSR fingerprint (SHA-256).',
        title='CSR fingerprint',
        group='event.est',
        example='0f2d7d8a...',
    ),
    ContextVar(
        'event.est.cert_profile',
        'string',
        'Requested certificate profile.',
        title='Certificate profile',
        group='event.est',
        example='tls-client',
    ),
    ContextVar(
        'event.est.csr_pem',
        'string',
        'CSR PEM payload.',
        title='CSR PEM',
        group='event.est',
    ),
)

REST_CONTEXT = ctx(
    ContextVar(
        'event.rest.operation',
        'string',
        'REST enrollment operation name.',
        title='REST operation',
        group='event.rest',
        example='enroll',
    ),
    ContextVar(
        'event.rest.fingerprint',
        'string',
        'CSR fingerprint (SHA-256).',
        title='CSR fingerprint',
        group='event.rest',
        example='0f2d7d8a...',
    ),
    ContextVar(
        'event.rest.cert_profile',
        'string',
        'Requested certificate profile.',
        title='Certificate profile',
        group='event.rest',
        example='tls-client',
    ),
    ContextVar(
        'event.rest.csr_pem',
        'string',
        'CSR PEM payload.',
        title='CSR PEM',
        group='event.rest',
    ),
)

SOURCE_CONTEXT = ctx(
    ContextVar(
        'event.source.trustpoint',
        'bool',
        'Event emitted trustpoint-wide.',
        title='Trustpoint-wide',
        group='event.source',
        example=True,
    ),
    ContextVar(
        'event.source.ca_id',
        'int',
        'CA id if present.',
        title='CA ID',
        group='event.source',
        example=7,
    ),
    ContextVar(
        'event.source.domain_id',
        'int',
        'Domain id if present.',
        title='Domain ID',
        group='event.source',
        example=42,
    ),
    ContextVar(
        'event.source.device_id',
        'string',
        'Device id if present.',
        title='Device ID',
        group='event.source',
        example='550e8400-e29b-41d4-a716-446655440000',
    ),
)
