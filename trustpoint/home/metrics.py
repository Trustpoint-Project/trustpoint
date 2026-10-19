# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Dashboard certificate health classification and aggregation.

The caller MUST provide a queryset of managed end-entity certificates.
This module deliberately does not equate every CertificateModel record with a
managed end-entity certificate: Trustpoint also stores CA/trust certificates.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from django.db.models import Count, Q, QuerySet
from django.utils import timezone

if TYPE_CHECKING:
    from pki.models import CertificateModel

CertificateHealth = Literal['valid', 'expiring', 'expired', 'revoked', 'not_yet_valid']
SUPPORTED_EXPIRY_DAYS = (7, 30, 90)


def classify_certificate(
    *,
    not_valid_before: datetime,
    not_valid_after: datetime,
    revoked: bool,
    as_of: datetime,
    expiry_days: int = 30,
) -> CertificateHealth:
    """Return the one health class for a certificate at a fixed instant.

    Revocation takes precedence. Boundaries are [not_before, not_after).
    The expiry window includes its upper endpoint.
    """
    if expiry_days not in SUPPORTED_EXPIRY_DAYS:
        msg = 'expiry_days must be 7, 30, or 90'
        raise ValueError(msg)
    if timezone.is_naive(as_of) or timezone.is_naive(not_valid_before) or timezone.is_naive(not_valid_after):
        msg = 'certificate validity dates and as_of must be timezone-aware'
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


def certificate_health_counts(
    managed_end_entity_certificates: QuerySet[CertificateModel],
    *,
    as_of: datetime | None = None,
    expiry_days: int = 30,
) -> dict[str, Any]:
    """Aggregate *provided* managed end-entity certificate population in DB.

    Caller owns permissions and scope filtering, including excluding CA and
    trust-only certificates. Fingerprint uniqueness on CertificateModel
    prevents identical imported certificates from being counted twice.
    """
    if expiry_days not in SUPPORTED_EXPIRY_DAYS:
        msg = 'expiry_days must be 7, 30, or 90'
        raise ValueError(msg)
    timestamp = as_of if as_of is not None else timezone.now()
    if timezone.is_naive(timestamp):
        msg = 'as_of must be timezone-aware'
        raise ValueError(msg)
    until = timestamp + timedelta(days=expiry_days)
    not_revoked = Q(revoked_certificate__isnull=True)
    current = Q(not_valid_before__lte=timestamp, not_valid_after__gt=timestamp)
    counts = managed_end_entity_certificates.aggregate(
        total=Count('pk', distinct=True),
        revoked=Count('pk', filter=Q(revoked_certificate__isnull=False), distinct=True),
        not_yet_valid=Count('pk', filter=not_revoked & Q(not_valid_before__gt=timestamp), distinct=True),
        expired=Count(
            'pk',
            filter=not_revoked & Q(not_valid_after__lte=timestamp) & Q(not_valid_before__lte=timestamp),
            distinct=True,
        ),
        expiring=Count('pk', filter=not_revoked & current & Q(not_valid_after__lte=until), distinct=True),
        valid=Count('pk', filter=not_revoked & current & Q(not_valid_after__gt=until), distinct=True),
    )
    classified = sum(counts[name] for name in ('valid', 'expiring', 'expired', 'revoked', 'not_yet_valid'))
    counts['unclassified'] = counts['total'] - classified
    counts['active'] = counts['valid'] + counts['expiring']
    counts['expiry_days'] = expiry_days
    counts['as_of'] = timestamp.isoformat()
    return counts
