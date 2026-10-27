# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Certificate health rules shared by models, presentation and database queries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from django.db.models import Count, Q
from django.utils import timezone

if TYPE_CHECKING:
    from collections.abc import Iterable

    from django.db.models import QuerySet

    from pki.models.certificate import CertificateModel

CertificateHealth = Literal['valid', 'expiring', 'not_yet_valid', 'expired', 'revoked']
CredentialHealth = Literal['valid', 'expiring', 'not_yet_valid', 'expired', 'revoked', 'none']
# Collections use their best available certificate. A usable identity wins over
# obsolete certificates; a future identity wins over expired or revoked ones.
HEALTH_PRIORITY: tuple[CertificateHealth, ...] = ('valid', 'expiring', 'not_yet_valid', 'expired', 'revoked')


def _validate_reference(as_of: datetime, expiry_days: int) -> None:
    if timezone.is_naive(as_of):
        msg = 'as_of must be timezone-aware'
        raise ValueError(msg)
    if expiry_days < 0:
        msg = 'expiry_days must be non-negative'
        raise ValueError(msg)


def classify_certificate(
    *,
    not_valid_before: datetime,
    not_valid_after: datetime,
    revoked: bool,
    as_of: datetime,
    expiry_days: int = 30,
) -> CertificateHealth:
    """Classify a certificate at one instant using [not_before, not_after).

    Revocation takes precedence over validity. The expiry window includes its
    upper endpoint. Zero days disables the separate expiring category.
    """
    _validate_reference(as_of, expiry_days)
    if timezone.is_naive(not_valid_before) or timezone.is_naive(not_valid_after):
        msg = 'certificate validity dates must be timezone-aware'
        raise ValueError(msg)
    if revoked:
        return 'revoked'
    if as_of < not_valid_before:
        return 'not_yet_valid'
    if as_of >= not_valid_after:
        return 'expired'
    if not_valid_after <= as_of + timedelta(days=expiry_days):
        return 'expiring'
    return 'valid'


def certificate_health_conditions(
    *,
    as_of: datetime,
    expiry_days: int = 30,
    prefix: str = '',
    revoked_condition: Q | None = None,
) -> dict[CertificateHealth, Q]:
    """Return disjoint SQL predicates matching the Python classification.

    A prefix may traverse single-valued relationships. For reverse or many-valued
    relationships use a correlated subquery so all predicates refer to one
    certificate. Historical callers can supply a revocation-time predicate.
    """
    _validate_reference(as_of, expiry_days)
    until = as_of + timedelta(days=expiry_days)
    revoked = (
        revoked_condition if revoked_condition is not None else Q(**{f'{prefix}revoked_certificate__isnull': False})
    )
    started = Q(**{f'{prefix}not_valid_before__lte': as_of})
    ended = Q(**{f'{prefix}not_valid_after__lte': as_of})
    current = ~revoked & started & ~ended
    expiring = Q(**{f'{prefix}not_valid_after__lte': until})
    return {
        'revoked': revoked,
        'not_yet_valid': ~revoked & Q(**{f'{prefix}not_valid_before__gt': as_of}),
        'expired': ~revoked & started & ended,
        'expiring': current & expiring,
        'valid': current & ~expiring,
    }


def certificate_health_counts(
    certificates: QuerySet[CertificateModel],
    *,
    as_of: datetime | None = None,
    expiry_days: int = 30,
) -> dict[str, Any]:
    """Aggregate the caller's certificate population at one fixed instant.

    The caller owns scope and permissions, including exclusion of trust-only or
    CA certificates when counting managed end-entity certificates.
    """
    timestamp = as_of if as_of is not None else timezone.now()
    conditions = certificate_health_conditions(as_of=timestamp, expiry_days=expiry_days)
    counts = certificates.aggregate(
        total=Count('pk', distinct=True),
        **{state: Count('pk', filter=condition, distinct=True) for state, condition in conditions.items()},
    )
    counts['unclassified'] = counts['total'] - sum(counts[state] for state in HEALTH_PRIORITY)
    counts['active'] = counts['valid'] + counts['expiring']
    counts['expiry_days'] = expiry_days
    counts['as_of'] = timestamp.isoformat()
    return counts


@dataclass(frozen=True)
class CertificateHealthSummary:
    """Health and dates for a collection of credential certificates."""

    state: CredentialHealth
    count: int
    next_expiry: datetime | None
    latest_expiry: datetime | None


def summarize_certificate_health(
    certificates: Iterable[CertificateModel],
    *,
    as_of: datetime,
    expiry_days: int = 7,
) -> CertificateHealthSummary:
    """Summarize a collection using the same priority as device SQL queries."""
    _validate_reference(as_of, expiry_days)
    states: set[CertificateHealth] = set()
    seen_certificates: set[int] = set()
    expiries = []
    active_expiries = []
    for certificate in certificates:
        if certificate.pk in seen_certificates:
            continue
        seen_certificates.add(certificate.pk)
        state = classify_certificate(
            not_valid_before=certificate.not_valid_before,
            not_valid_after=certificate.not_valid_after,
            revoked=hasattr(certificate, 'revoked_certificate'),
            as_of=as_of,
            expiry_days=expiry_days,
        )
        states.add(state)
        expiries.append(certificate.not_valid_after)
        if state in ('valid', 'expiring'):
            active_expiries.append(certificate.not_valid_after)
    return CertificateHealthSummary(
        state=next((state for state in HEALTH_PRIORITY if state in states), 'none'),
        count=len(expiries),
        next_expiry=min(active_expiries, default=None),
        latest_expiry=max(expiries, default=None),
    )
