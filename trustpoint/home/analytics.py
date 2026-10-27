# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Read-only detail analytics for the additive Dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.http import JsonResponse
from django.utils import timezone
from django.views import View

from devices.dashboard_filters import (
    filter_devices_with_active_application_certificates,
    filter_devices_with_expired_or_revoked_application_certificates,
)
from devices.health import filter_credential_health
from devices.models import DeviceModel
from home.views import DashboardChartsAndCountsView
from pki.models import CaModel, IssuedCredentialModel
from pki.services.certificate_health import certificate_health_conditions, classify_certificate

if TYPE_CHECKING:
    from django.http import HttpRequest

SUPPORTED_DAYS = (7, 30, 90)


def application_certificate_device_counts(now: datetime) -> dict[str, int]:
    """Count devices across both onboarding modes; bucket each device only once.

    This chart counts devices, not individual application certificates. Devices with
    both active and old/expired certificates belong to the active category.
    """
    devices = DeviceModel.objects.all()
    active = set(filter_devices_with_active_application_certificates(devices, now).values_list('pk', flat=True))
    bad = (
        set(filter_devices_with_expired_or_revoked_application_certificates(devices, now).values_list('pk', flat=True))
        - active
    )
    future = set(filter_credential_health(
        devices, IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        ['not_yet_valid'], as_of=now,
    ).values_list('pk', flat=True)) - active - bad
    return {
        'active': len(active),
        'expired_or_revoked_only': len(bad),
        'not_yet_valid': len(future),
        'none': devices.count() - len(active) - len(bad) - len(future),
    }


def onboarding_domain_credentials_expiring(now: datetime, days: int) -> int:
    """Distinct onboarded-mode devices with a currently valid credential expiring in the selected horizon."""
    horizon = now + timedelta(days=days)
    current = certificate_health_conditions(
        as_of=now, expiry_days=0, prefix='credential__certificate__',
    )['valid']
    expiring_devices = IssuedCredentialModel.objects.filter(
        current,
        issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        credential__certificate__not_valid_after__lte=horizon,
    ).values('device_id')
    return (
        DeviceModel.objects.filter(
            onboarding_config__isnull=False,
            pk__in=expiring_devices,
        )
        .distinct()
        .count()
    )


def device_domain_counts() -> list[dict[str, Any]]:
    """Group ALL registered devices by their actual DeviceModel.domain FK."""
    groups = list(
        DeviceModel.objects.values('domain_id', 'domain__unique_name')
        .annotate(count=Count('pk'))
        .order_by('domain__unique_name')
    )
    return [
        {
            'name': row['domain__unique_name'] or 'No domain assigned',
            'domain_id': row['domain_id'],
            'count': row['count'],
        }
        for row in groups
    ]


def issuing_ca_status_and_suites(now: datetime, expiry_days: int) -> tuple[dict[str, int], dict[str, int]]:
    """Classify configured issuing CAs and summarize their configured signature suites.

    Does not claim that external services are online or available.
    CA identity is determined by CaModel.ca_type, not certificate-chain records.
    """
    excluded_types = (
        CaModel.CaTypeChoice.KEYLESS,
        CaModel.CaTypeChoice.REMOTE_EST_RA,
        CaModel.CaTypeChoice.REMOTE_CMP_RA,
    )
    cas = CaModel.objects.exclude(ca_type__in=excluded_types).select_related(
        'credential__certificate__revoked_certificate',
    )
    status = dict.fromkeys(
        ('active', 'expiring', 'expired', 'revoked', 'not_yet_valid', 'disabled', 'no_certificate'), 0,
    )
    suites: dict[str, int] = {}
    for ca in cas:
        cert = ca.credential.certificate if ca.credential_id and ca.credential else None
        if not ca.is_active:
            key = 'disabled'
        elif cert is None:
            key = 'no_certificate'
        else:
            health = classify_certificate(
                not_valid_before=cert.not_valid_before, not_valid_after=cert.not_valid_after,
                revoked=hasattr(cert, 'revoked_certificate'), as_of=now, expiry_days=expiry_days,
            )
            key = 'active' if health == 'valid' else health
        status[key] += 1
        try:
            display = str(ca.signature_suite_display) if cert is not None else 'Unavailable'
        except (AttributeError, ValueError, TypeError):
            display = 'Unavailable'
        suites[display] = suites.get(display, 0) + 1
    return status, suites


def issuing_ca_type_counts() -> dict[str, int]:
    """Count configured CA types including RA modes, excluding keyless anchors."""
    qs = CaModel.objects.exclude(ca_type=CaModel.CaTypeChoice.KEYLESS)
    return {
        str(label): qs.filter(ca_type=value).count()
        for value, label in CaModel.CaTypeChoice.choices
        if value != CaModel.CaTypeChoice.KEYLESS
    }


def issuing_ca_crl_summary(now: datetime) -> dict[str, int]:
    """Summarize active CRL freshness without verifying publication reachability."""
    cas = CaModel.objects.exclude(
        ca_type__in=(
            CaModel.CaTypeChoice.KEYLESS,
            CaModel.CaTypeChoice.REMOTE_EST_RA,
            CaModel.CaTypeChoice.REMOTE_CMP_RA,
        )
    ).prefetch_related('crls')
    result = {'current': 0, 'expired': 0, 'not_yet_valid': 0, 'missing': 0}
    for ca in cas:
        crl = next((entry for entry in ca.crls.all() if entry.is_active), None)
        if crl is None:
            result['missing'] += 1
        elif crl.this_update > now:
            result['not_yet_valid'] += 1
        elif crl.next_update is None or crl.next_update <= now:
            result['expired'] += 1
        else:
            result['current'] += 1
    return result


class DashboardAnalyticsAPIView(LoginRequiredMixin, View):
    """Tab-specific read-only analytics, using snapshot and period filters explicitly."""

    http_method_names = ('get', 'head', 'options')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        """Return analytics for the selected tab and time filters."""
        del args, kwargs
        tab = request.GET.get('tab', '')
        if tab not in ('certificates', 'devices', 'cas'):
            return JsonResponse({'error': 'Invalid tab'}, status=400)
        try:
            activity_days = int(request.GET.get('activity_days', '30'))
            expiry_days = int(request.GET.get('expiry_days', '30'))
        except (TypeError, ValueError):
            return JsonResponse({'error': 'Invalid time filter'}, status=400)
        if activity_days not in SUPPORTED_DAYS or expiry_days not in SUPPORTED_DAYS:
            return JsonResponse({'error': 'Only 7, 30, or 90 days supported'}, status=400)

        now = timezone.now()
        since = now - timedelta(days=activity_days)
        legacy = DashboardChartsAndCountsView()
        groups: dict[str, Any]
        if tab == 'certificates':
            groups = {
                'by_profile': legacy.get_cert_counts_by_profile(since, now),
                'by_issuing_ca': legacy.get_cert_counts_by_issuing_ca(since, now),
                # The five-state managed certificate breakdown is rendered from the Overview API.
            }
            note = (
                'Historical issuance groups use their legacy data scope; certificate health uses '
                'the separately labeled device-linked scope.'
            )
        elif tab == 'devices':
            enrollment = legacy.get_device_enrollment_counts(None)
            # Total is a summary, not a fourth enrollment bucket.
            enrollment.pop('total', None)
            domain_credentials = legacy.get_device_domain_credential_counts(now)
            domain_credentials.pop('total', None)
            protocol = legacy.get_device_count_by_onboarding_protocol(None)
            groups = {
                'by_enrollment': enrollment,
                'by_domain_credential': domain_credentials,
                'by_application_certificate': application_certificate_device_counts(now),
                'by_protocol': protocol,
                'by_domain': device_domain_counts(),
                'expiring_domain_credentials': {
                    'expiring_within_selected_horizon': onboarding_domain_credentials_expiring(now, expiry_days)
                },
            }
            note = (
                'Device charts are current snapshots. Domain credentials and enrollment protocols '
                'apply only to devices using onboarding. Application certificate states cover all devices.'
            )
        else:
            status, suites = issuing_ca_status_and_suites(now, expiry_days)
            groups = {
                'status': status,
                'ca_types': issuing_ca_type_counts(),
                'crl_freshness': issuing_ca_crl_summary(now),
                'signature_suites': suites,
            }
            note = 'CA status uses the selected expiry horizon; enabled does not mean live service availability.'
        return JsonResponse(
            {
                'tab': tab,
                'as_of': now.isoformat(),
                'activity_days': activity_days,
                'expiry_days': expiry_days,
                'historical_period_start': since.isoformat(),
                'groups': groups,
                'note': note,
            }
        )
