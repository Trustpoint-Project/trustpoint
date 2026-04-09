"""Shared device dashboard status filters."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from django.db.models import Q, QuerySet
from django.utils import timezone

from onboarding.models import OnboardingStatus
from pki.models.issued_credential import IssuedCredentialModel

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


def filter_active_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices counted as active on the dashboard."""
    return queryset.filter(
        Q(no_onboarding_config__isnull=False) |
        Q(onboarding_config__onboarding_status=OnboardingStatus.ONBOARDED)
    ).distinct()


def filter_pending_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices counted as pending on the dashboard."""
    return queryset.filter(
        onboarding_config__onboarding_status=OnboardingStatus.PENDING
    ).distinct()


def filter_no_onboarding_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices that use no onboarding."""
    return queryset.filter(no_onboarding_config__isnull=False).distinct()


def filter_onboarded_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices that completed onboarding."""
    return queryset.filter(
        onboarding_config__onboarding_status=OnboardingStatus.ONBOARDED
    ).distinct()


def filter_devices_without_domain_credential(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices without a domain credential."""
    return queryset.exclude(DOMAIN_CREDENTIAL_Q).distinct()


def filter_devices_with_valid_domain_credential(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices with a domain credential valid beyond the expiring window."""
    now = reference_time or timezone.now()
    next_7_days = now + timedelta(days=7)
    return queryset.filter(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=next_7_days,
    ).distinct()


def filter_devices_with_expiring_domain_credential_in_1_day(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices whose best domain credential state is expiring within 24 hours."""
    now = reference_time or timezone.now()
    next_1_day = now + timedelta(days=1)
    next_7_days = now + timedelta(days=7)
    return queryset.filter(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=now,
        issued_credentials__credential__certificate__not_valid_after__lte=next_1_day,
    ).exclude(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=next_7_days,
    ).distinct()


def filter_devices_with_expiring_domain_credential_in_7_days(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices whose best domain credential state is expiring within 1 to 7 days."""
    now = reference_time or timezone.now()
    next_1_day = now + timedelta(days=1)
    next_7_days = now + timedelta(days=7)
    return queryset.filter(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=next_1_day,
        issued_credentials__credential__certificate__not_valid_after__lte=next_7_days,
    ).exclude(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=next_7_days,
    ).exclude(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=now,
        issued_credentials__credential__certificate__not_valid_after__lte=next_1_day,
    ).distinct()


def filter_devices_with_expiring_domain_credential(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices whose best domain credential state is expiring within 7 days."""
    now = reference_time or timezone.now()
    next_7_days = now + timedelta(days=7)
    return queryset.filter(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=now,
        issued_credentials__credential__certificate__not_valid_after__lte=next_7_days,
    ).exclude(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=next_7_days,
    ).distinct()


def filter_devices_with_expired_domain_credential(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices whose domain credentials are all expired.

    Devices without any domain credential are excluded from this queryset.
    """
    now = reference_time or timezone.now()
    return queryset.filter(
        DOMAIN_CREDENTIAL_Q,
    ).exclude(
        DOMAIN_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=now,
    ).distinct()


def filter_expired_devices(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Backward-compatible alias for expired domain-credential devices."""
    return filter_devices_with_expired_domain_credential(queryset)


def filter_devices_without_application_certificates(queryset: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
    """Return devices without application certificates."""
    return queryset.exclude(APPLICATION_CREDENTIAL_Q).distinct()


def filter_devices_with_active_application_certificates(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices with at least one active application certificate."""
    now = reference_time or timezone.now()
    return queryset.filter(
        APPLICATION_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=now,
    ).distinct()


def filter_devices_with_expired_application_certificates(
    queryset: QuerySet[DeviceModel],
    reference_time: datetime | None = None,
) -> QuerySet[DeviceModel]:
    """Return devices whose application certificates are all expired."""
    now = reference_time or timezone.now()
    return queryset.filter(
        APPLICATION_CREDENTIAL_Q,
    ).exclude(
        APPLICATION_CREDENTIAL_Q,
        issued_credentials__credential__certificate__not_valid_after__gt=now,
    ).distinct()
