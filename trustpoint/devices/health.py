# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Device credential health shared by badges, filtering and sorting."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db.models import Case, CharField, Exists, IntegerField, OuterRef, Value, When
from django.utils import timezone

from pki.models import IssuedCredentialModel
from pki.services.certificate_health import HEALTH_PRIORITY, certificate_health_conditions, summarize_certificate_health

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from django.db.models import QuerySet

    from devices.models import DeviceModel
    from pki.models import CertificateModel
    from pki.services.certificate_health import CertificateHealthSummary, CredentialHealth

DEVICE_EXPIRY_DAYS = 7
DOMAIN_HEALTH_RANKS: dict[CredentialHealth, int] = {
    'none': 0,
    'valid': 1,
    'expiring': 2,
    'not_yet_valid': 3,
    'expired': 4,
    'revoked': 5,
}
APPLICATION_HEALTH_RANKS: dict[CredentialHealth, int] = {
    'none': 0,
    'valid': 1,
    'expiring': 1,
    'not_yet_valid': 2,
    'expired': 3,
    'revoked': 4,
}


def credential_certificates(
    device: DeviceModel,
    credential_type: IssuedCredentialModel.IssuedCredentialType,
) -> list[CertificateModel]:
    """Read a device's credential certificates, using prefetched records when available."""
    return [
        issued.credential.certificate
        for issued in device.issued_credentials.all()
        if issued.issued_credential_type == credential_type and issued.credential.certificate is not None
    ]


def device_credential_health(
    device: DeviceModel,
    credential_type: IssuedCredentialModel.IssuedCredentialType,
    *,
    as_of: datetime | None = None,
) -> CertificateHealthSummary:
    """Classify the primary certificates of one device's selected credential type."""
    return summarize_certificate_health(
        credential_certificates(device, credential_type),
        as_of=as_of if as_of is not None else timezone.now(),
        expiry_days=DEVICE_EXPIRY_DAYS,
    )


def credential_health_expression(
    credential_type: IssuedCredentialModel.IssuedCredentialType,
    *,
    as_of: datetime,
    expiry_days: int = DEVICE_EXPIRY_DAYS,
    state_values: Mapping[CredentialHealth, int] | None = None,
) -> Case:
    """Classify each device, optionally returning sort ranks with the same predicates."""
    credentials = IssuedCredentialModel.objects.filter(
        device_id=OuterRef('pk'),
        issued_credential_type=credential_type,
        credential__certificate__isnull=False,
    )
    conditions = certificate_health_conditions(
        as_of=as_of,
        expiry_days=expiry_days,
        prefix='credential__certificate__',
    )
    return Case(
        *[
            When(
                Exists(credentials.filter(conditions[state])),
                then=Value(state if state_values is None else state_values[state]),
            )
            for state in HEALTH_PRIORITY
        ],
        default=Value('none' if state_values is None else state_values['none']),
        output_field=CharField() if state_values is None else IntegerField(),
    )


def filter_credential_health(
    queryset: QuerySet[DeviceModel],
    credential_type: IssuedCredentialModel.IssuedCredentialType,
    states: Sequence[CredentialHealth],
    *,
    as_of: datetime | None = None,
    expiry_days: int = DEVICE_EXPIRY_DAYS,
) -> QuerySet[DeviceModel]:
    """Filter devices using exactly the same collection priority as their badges."""
    return queryset.alias(
        _credential_health=credential_health_expression(
            credential_type,
            as_of=as_of if as_of is not None else timezone.now(),
            expiry_days=expiry_days,
        ),
    ).filter(_credential_health__in=states)
