# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Display helpers shared by device and owner-credential pages."""

from __future__ import annotations

import datetime as dt
from functools import cached_property
from typing import TYPE_CHECKING, Any

from django.utils import timezone
from django.utils.translation import gettext_lazy

from devices.health import device_credential_health
from onboarding.enums import OnboardingStatus
from pki.models import IssuedCredentialModel
from pki.models.certificate import CertificateModel

if TYPE_CHECKING:
    from devices.models import DeviceModel
    from pki.models import RemoteIssuedCredentialModel


def credential_health_display(
    record: DeviceModel,
    credential_type: IssuedCredentialModel.IssuedCredentialType,
    *,
    as_of: dt.datetime,
) -> dict[str, str]:
    """Render shared health facts while keeping presentation out of classification."""
    summary = device_credential_health(record, credential_type, as_of=as_of)
    is_application = credential_type == IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
    state = 'active' if is_application and summary.state in ('valid', 'expiring') else summary.state
    labels = {
        'none': gettext_lazy('None'),
        'valid': gettext_lazy('Valid'),
        'expiring': gettext_lazy('Expiring'),
        'active': gettext_lazy('Active'),
        'not_yet_valid': gettext_lazy('Not yet valid'),
        'expired': gettext_lazy('Expired'),
        'revoked': gettext_lazy('Revoked'),
    }
    if summary.count == 0:
        tooltip = str(
            gettext_lazy('No application certificates issued.') if is_application
            else gettext_lazy('No domain credential issued.')
        )
    else:
        date = summary.next_expiry or summary.latest_expiry
        date_label = gettext_lazy('Next expiry') if summary.next_expiry else gettext_lazy('Latest expiry')
        display_date = timezone.localtime(date).strftime('%Y-%m-%d %H:%M') if date else '—'
        tooltip = (
            f'<strong>{gettext_lazy("Certificates")}:</strong> {summary.count}<br>'
            f'<strong>{date_label}:</strong> {display_date}'
        )
    return {'status_key': state, 'status_label': str(labels[state]), 'tooltip': tooltip}


class DeviceHealthPresentationMixin:
    """Give list views a fixed health timestamp and identical credential badges."""

    @cached_property
    def health_as_of(self) -> dt.datetime:
        """Use one instant for badge rendering, counts and SQL sorting."""
        return timezone.now()

    def _get_domain_credential_status(self, record: DeviceModel) -> dict[str, str]:
        """Render domain credential health."""
        return credential_health_display(
            record, IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL, as_of=self.health_as_of,
        )

    def _get_application_certificate_status(self, record: DeviceModel) -> dict[str, str]:
        """Render application credential health."""
        return credential_health_display(
            record, IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL, as_of=self.health_as_of,
        )


def credential_expiry_display(record: IssuedCredentialModel | RemoteIssuedCredentialModel) -> str:
    """Display the certificate status or the remaining credential lifetime."""
    cert = record.credential.certificate_or_error
    if cert.certificate_status != CertificateModel.CertificateStatus.OK:
        return str(cert.certificate_status.label)
    remaining = cert.not_valid_after - dt.datetime.now(dt.UTC)
    hours, remainder = divmod(remaining.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f'{remaining.days} days, {hours}:{minutes:02d}:{seconds:02d}'


def pki_protocols_display(record: DeviceModel) -> str:
    """Display enabled PKI protocols from the device's enrollment configuration."""
    config = record.onboarding_config or record.no_onboarding_config
    return ', '.join(str(protocol.label) for protocol in config.get_pki_protocols()) if config else ''


def onboarding_progress(
    record: DeviceModel,
    *,
    empty_protocols_label: str,
    unconfigured_label: str,
    unconfigured_tooltip: str,
) -> dict[str, Any]:
    """Build enrollment badges and tooltips using the page's existing fallback text."""
    config = record.onboarding_config or record.no_onboarding_config
    labels = [str(protocol.label) for protocol in config.get_pki_protocols()] if config else []
    none_label = str(gettext_lazy('None'))
    protocol_list = ''.join(f'<li>{label}</li>' for label in labels) if labels else f'<li>{none_label}</li>'
    protocol_display = ', '.join(labels) if labels else empty_protocols_label

    if record.onboarding_config:
        is_onboarded = record.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED
        status_key = 'onboarded' if is_onboarded else 'pending'
        status_label = str(gettext_lazy('Onboarded') if is_onboarded else gettext_lazy('Pending'))
        onboarding_protocol = str(record.onboarding_config.get_onboarding_protocol_display())
        tooltip = (
            f'<strong>{gettext_lazy("Onboarding Protocol")}:</strong> {onboarding_protocol}<br>'
            f'<strong>{gettext_lazy("Status")}:</strong> {status_label}<br>'
            f'<strong>{gettext_lazy("PKI Protocols")}:</strong>'
            f'<ul class="mb-0 ps-3 mt-1">{protocol_list}</ul>'
        )
    elif record.no_onboarding_config:
        status_key = 'no-onboarding'
        status_label = str(gettext_lazy('No onboarding'))
        onboarding_protocol = '—'
        tooltip = (
            f'<strong>{gettext_lazy("Enrollment")}:</strong> {gettext_lazy("No onboarding")}<br>'
            f'<strong>{gettext_lazy("PKI Protocols")}:</strong>'
            f'<ul class="mb-0 ps-3 mt-1">{protocol_list}</ul>'
        )
    else:
        status_key = 'none'
        status_label = unconfigured_label
        onboarding_protocol = protocol_display = '—'
        tooltip = unconfigured_tooltip

    return {
        'status_key': status_key,
        'status_label': status_label,
        'onboarding_protocol': onboarding_protocol,
        'pki_protocols': protocol_display,
        'tooltip': tooltip,
    }
