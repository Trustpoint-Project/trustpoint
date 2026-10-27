# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Device dashboard filters using shared certificate and credential health rules."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from django.db.models import Exists, OuterRef, Q, QuerySet
from django.utils import timezone

from devices.health import filter_credential_health
from onboarding.models import OnboardingStatus
from pki.models.issued_credential import IssuedCredentialModel
from pki.services.certificate_health import certificate_health_conditions

if TYPE_CHECKING:
    from devices.models import DeviceModel

DOMAIN_CREDENTIAL_Q = Q(
    issued_credentials__issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
    issued_credentials__credential__certificate__isnull=False,
)
APPLICATION_CREDENTIAL_Q = Q(
    issued_credentials__issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
    issued_credentials__credential__certificate__isnull=False,
)
DOMAIN = IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
APPLICATION = IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL


def filter_active_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices counted as enrolled/active independently of certificate health."""
    return queryset.filter(
        Q(no_onboarding_config__isnull=False) | Q(onboarding_config__onboarding_status=OnboardingStatus.ONBOARDED)
    ).distinct()


def filter_pending_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices that have pending onboarding."""
    return queryset.filter(onboarding_config__onboarding_status=OnboardingStatus.PENDING).distinct()


def filter_no_onboarding_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices that use no onboarding."""
    return queryset.filter(no_onboarding_config__isnull=False).distinct()


def filter_onboarded_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices that completed onboarding."""
    return queryset.filter(onboarding_config__onboarding_status=OnboardingStatus.ONBOARDED).distinct()


def filter_devices_without_domain_credential(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices with no issued domain certificate, excluding key-only credentials."""
    return filter_credential_health(queryset, DOMAIN, ['none'])


def filter_devices_with_valid_domain_credential(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices with a currently valid domain credential beyond seven days."""
    return filter_credential_health(queryset, DOMAIN, ['valid'], as_of=reference_time)


def filter_devices_with_expiring_domain_credential(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices whose best usable domain credential expires within seven days."""
    return filter_credential_health(queryset, DOMAIN, ['expiring'], as_of=reference_time)


def _filter_domain_expiry_window(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None,
    lower_days: int,
    upper_days: int,
) -> QuerySet[DeviceModel]:
    """Bucket devices by their earliest active expiry, unless a longer-lived identity exists."""
    now = reference_time if reference_time is not None else timezone.now()
    expiring = filter_credential_health(
        queryset,
        DOMAIN,
        ['expiring'],
        as_of=now,
        expiry_days=max(7, upper_days),
    )
    current = certificate_health_conditions(as_of=now, expiry_days=0, prefix='credential__certificate__')['valid']
    credentials = IssuedCredentialModel.objects.filter(
        current,
        device_id=OuterRef('pk'),
        issued_credential_type=DOMAIN,
        credential__certificate__isnull=False,
    )
    within = Exists(credentials.filter(credential__certificate__not_valid_after__lte=now + timedelta(days=upper_days)))
    result = expiring.filter(within)
    if lower_days:
        earlier = Exists(
            credentials.filter(credential__certificate__not_valid_after__lte=now + timedelta(days=lower_days))
        )
        result = result.filter(~earlier)
    return result


def filter_devices_with_expiring_domain_credential_in_1_day(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return expiring devices whose earliest active domain certificate expires within 24 hours."""
    return _filter_domain_expiry_window(queryset, reference_time, 0, 1)


def filter_devices_with_expiring_domain_credential_in_7_days(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return expiring devices whose earliest active domain certificate expires in one to seven days."""
    return _filter_domain_expiry_window(queryset, reference_time, 1, 7)


def filter_devices_with_expiring_domain_credential_in_30_days(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices whose earliest active domain expiry is seven to thirty days away."""
    return _filter_domain_expiry_window(queryset, reference_time, 7, 30)


def filter_devices_with_expired_or_revoked_domain_credential(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices with only expired or revoked domain certificates."""
    return filter_credential_health(queryset, DOMAIN, ['expired', 'revoked'], as_of=reference_time)


def filter_expired_or_revoked_devices(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return expired/revoked domain identities, or application identities when no domain identity exists."""
    now = reference_time if reference_time is not None else timezone.now()
    bad_domain = filter_devices_with_expired_or_revoked_domain_credential(queryset, now)
    bad_application_only = filter_devices_with_expired_or_revoked_application_certificates(
        filter_devices_without_domain_credential(queryset),
        now,
    )
    return queryset.filter(Q(pk__in=bad_domain.values('pk')) | Q(pk__in=bad_application_only.values('pk'))).distinct()


def filter_devices_without_application_certificates(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices with no issued application certificate."""
    return filter_credential_health(queryset, APPLICATION, ['none'])


def filter_devices_with_active_application_certificates(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices with a currently valid application certificate."""
    return filter_credential_health(queryset, APPLICATION, ['valid', 'expiring'], as_of=reference_time)


def filter_devices_with_expired_or_revoked_application_certificates(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices with only expired or revoked application certificates."""
    return filter_credential_health(queryset, APPLICATION, ['expired', 'revoked'], as_of=reference_time)
