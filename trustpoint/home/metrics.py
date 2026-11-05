# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Dashboard adapters for the shared PKI certificate health service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pki.services.certificate_health import CertificateHealth
from pki.services.certificate_health import certificate_health_counts as _certificate_health_counts
from pki.services.certificate_health import classify_certificate as _classify_certificate

if TYPE_CHECKING:
    from datetime import datetime

    from django.db.models import QuerySet

    from pki.models import CertificateModel

SUPPORTED_EXPIRY_DAYS = (7, 30, 90)


def _validate_expiry_days(expiry_days: int) -> None:
    if expiry_days not in SUPPORTED_EXPIRY_DAYS:
        msg = 'expiry_days must be 7, 30, or 90'
        raise ValueError(msg)


def classify_certificate(
    *,
    not_valid_before: datetime,
    not_valid_after: datetime,
    revoked: bool,
    as_of: datetime,
    expiry_days: int = 30,
) -> CertificateHealth:
    """Classify using the dashboard's supported expiry windows."""
    _validate_expiry_days(expiry_days)
    return _classify_certificate(
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        revoked=revoked,
        as_of=as_of,
        expiry_days=expiry_days,
    )


def certificate_health_counts(
    managed_end_entity_certificates: QuerySet[CertificateModel],
    *,
    as_of: datetime | None = None,
    expiry_days: int = 30,
) -> dict[str, Any]:
    """Count the caller's managed end-entity scope using dashboard expiry windows."""
    _validate_expiry_days(expiry_days)
    return _certificate_health_counts(managed_end_entity_certificates, as_of=as_of, expiry_days=expiry_days)
