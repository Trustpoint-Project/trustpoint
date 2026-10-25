# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Display helpers shared by device and owner-credential pages."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any

from django.utils.translation import gettext_lazy

from onboarding.enums import OnboardingStatus
from pki.models.certificate import CertificateModel

if TYPE_CHECKING:
    from devices.models import DeviceModel
    from pki.models import IssuedCredentialModel, RemoteIssuedCredentialModel


def credential_expiry_display(record: IssuedCredentialModel | RemoteIssuedCredentialModel) -> str:
    """Display the certificate status or the remaining credential lifetime."""
    cert = record.credential.certificate_or_error
    if cert.certificate_status != CertificateModel.CertificateStatus.OK:
        return str(cert.certificate_status.label)
    remaining = cert.not_valid_after - datetime.datetime.now(datetime.UTC)
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
