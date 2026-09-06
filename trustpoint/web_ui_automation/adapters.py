# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Concrete implementation of the credential issuance adapter for Web UI automation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from devices.issuer import LocalTlsServerCredentialIssuer
from pki.models.cert_profile import CertificateProfileModel
from web_ui_automation.issuance import PreparedCredential
from web_ui_automation.schema import get_certificate_profile_slug

if TYPE_CHECKING:
    from web_ui_automation.models import WebUiAutomationAssignedProfile


class TrustpointIssuanceAdapter:
    """Adapter to issue certificates using Trustpoint's certificate profile system."""

    def prepare_onboarding(self, assignment: WebUiAutomationAssignedProfile) -> PreparedCredential:
        """Issue the initial credential using the profile's certificate-profile slug."""
        profile_slug = get_certificate_profile_slug(assignment.workflow_definition.profile)

        if not CertificateProfileModel.objects.filter(unique_name=profile_slug).exists():
            raise ValidationError(
                _('Certificate profile "%(slug)s" does not exist.') % {'slug': profile_slug}
            )

        device = assignment.automation_device.device
        if not device:
            raise ValidationError(_('No device linked to this Web UI automation device.'))

        if not device.domain:
            raise ValidationError(_('Device has no domain configured.'))

        issuer = LocalTlsServerCredentialIssuer(device=device, domain=device.domain)

        domain_names = [device.common_name]

        issued_credential = issuer.issue_tls_server_credential(
            common_name=device.common_name,
            ipv4_addresses=[],
            ipv6_addresses=[],
            domain_names=domain_names,
            validity_days=365,
        )

        return PreparedCredential(
            issued_credential=issued_credential,
            candidate_certificate=issued_credential.credential.certificate_or_error,
        )

    def prepare_renewal(self, assignment: WebUiAutomationAssignedProfile) -> PreparedCredential:
        """Issue a replacement certificate using the existing private key."""
        if not assignment.issued_credential:
            raise ValidationError(_('No issued credential to renew.'))

        profile_slug = get_certificate_profile_slug(assignment.workflow_definition.profile)

        if not CertificateProfileModel.objects.filter(unique_name=profile_slug).exists():
            raise ValidationError(
                _('Certificate profile "%(slug)s" does not exist.') % {'slug': profile_slug}
            )

        device = assignment.automation_device.device
        if not device:
            raise ValidationError(_('No device linked to this Web UI automation device.'))

        if not device.domain:
            raise ValidationError(_('Device has no domain configured.'))

        existing_credential = assignment.issued_credential.credential
        if not existing_credential or not existing_credential.private_key:
            raise ValidationError(_('No private key found in existing credential.'))

        issuer = LocalTlsServerCredentialIssuer(device=device, domain=device.domain)

        domain_names = [device.common_name]

        private_key_serializer = existing_credential.get_private_key_serializer()
        public_key = private_key_serializer.public_key_serializer.as_crypto()
        issued_credential = issuer.issue_tls_server_certificate(
            common_name=device.common_name,
            ipv4_addresses=[],
            ipv6_addresses=[],
            domain_names=domain_names,
            validity_days=365,
            public_key=public_key,
        )

        return PreparedCredential(
            issued_credential=issued_credential,
            candidate_certificate=issued_credential.credential.certificate_or_error,
        )
