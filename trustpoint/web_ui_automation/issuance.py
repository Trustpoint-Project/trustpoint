# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Adapter boundary to Trustpoint's certificate-profile-driven issuance services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

if TYPE_CHECKING:
    from pki.models.certificate import CertificateModel
    from pki.models.issued_credential import IssuedCredentialModel
    from web_ui_automation.models import WebUiAutomationAssignedProfile


@dataclass(frozen=True, slots=True)
class PreparedCredential:
    """Credential objects prepared before browser execution."""

    issued_credential: IssuedCredentialModel
    candidate_certificate: CertificateModel


class CredentialIssuanceAdapter(Protocol):
    """Interface implemented by the existing Trustpoint issuance layer."""

    def prepare_onboarding(self, assignment: WebUiAutomationAssignedProfile) -> PreparedCredential:
        """Issue the initial credential using the profile's fixed certificate-profile slug."""

    def prepare_renewal(self, assignment: WebUiAutomationAssignedProfile) -> PreparedCredential:
        """Issue a replacement certificate using the existing private key."""


class NotConfiguredIssuanceAdapter:
    """Fail explicitly until the repository-specific issuance adapter is configured."""

    def prepare_onboarding(self, _assignment: WebUiAutomationAssignedProfile) -> PreparedCredential:
        """Raise a configuration error for onboarding."""
        msg = 'Configure WEB_UI_AUTOMATION_ISSUANCE_ADAPTER with a Trustpoint issuance adapter.'
        raise ImproperlyConfigured(
            msg
        )

    def prepare_renewal(self, _assignment: WebUiAutomationAssignedProfile) -> PreparedCredential:
        """Raise a configuration error for renewal."""
        msg = 'Configure WEB_UI_AUTOMATION_ISSUANCE_ADAPTER with a Trustpoint issuance adapter.'
        raise ImproperlyConfigured(
            msg
        )


def get_issuance_adapter() -> CredentialIssuanceAdapter:
    """Load the configured issuance adapter from Django settings."""
    dotted_path = getattr(
        settings,
        'WEB_UI_AUTOMATION_ISSUANCE_ADAPTER',
        'web_ui_automation.issuance.NotConfiguredIssuanceAdapter',
    )
    adapter_class = import_string(dotted_path)
    return adapter_class()
