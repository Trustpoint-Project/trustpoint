# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Abstract CMP request wizard, independent of the requested certificate type.

Reuses the protocol-neutral certificate request wizard
(``pki/views/est_request.py``) and only adds the CMP-specific authentication
and enrollment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pki.services.cmp_enrollment import enroll_cmp
from pki.services.external_csr import external_csr_profile
from pki.views.est_request import CertificateRequestCertView, CertificateRequestView
from request.clients.cmp_client import CmpClientError
from request.request_context import CmpCertificateRequestContext

if TYPE_CHECKING:
    from cryptography import x509

    from pki.models import CredentialModel
    from pki.models.cert_profile import CertificateProfileModel
    from pki.models.truststore import TruststoreModel

__all__ = ['CmpRequestCertView', 'CmpRequestView']


class CmpRequestView(CertificateRequestView):
    """Step 1 (CMP): generate the key and configure the external CMP PKI."""

    title = 'Request Certificate via CMP'
    description = 'Generate a keypair and request the certificate from an external PKI via CMP.'
    section_title = 'CMP Request'
    section_description = 'The key type and the external CMP endpoint used for the request.'


class CmpRequestCertView(CertificateRequestCertView):
    """Step 4 (CMP): review the request, then enroll the certificate via CMP."""

    title = 'Request Certificate via CMP'
    description = 'Review the request and enroll the certificate from the external PKI via CMP.'
    client_error_types = (CmpClientError,)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the CMP sender KID and shared-secret status to the review page."""
        context = super().get_context_data(**kwargs)
        context['cmp_sender_kid'] = self.state.get('cmp_sender_kid')
        context['cmp_shared_secret_set'] = bool(self.state.get('cmp_shared_secret'))
        return context

    def build_enrollment_context(
        self,
        credential: CredentialModel,
        profile: CertificateProfileModel,
        content: dict[str, Any],
        truststore: TruststoreModel,
    ) -> CmpCertificateRequestContext:
        """Build the CMP enrollment context from the stored configuration."""
        context = CmpCertificateRequestContext(
            operation='certification',
            protocol='cmp',
            domain=None,
            cert_profile_str=profile.unique_name,
            certificate_profile_model=external_csr_profile(profile),
            allow_ca_certificate_request=self.allow_ca_certificate_request,
            cmp_server_host=self.state['remote_host'],
            cmp_server_port=self.state['remote_port'],
            cmp_server_path=self.state['remote_path'],
            cmp_shared_secret=self.state['cmp_shared_secret'],
            cmp_server_truststore=truststore,
        )
        context.request_data = self.build_request_data_for_enrollment(content)
        context.owner_credential = credential
        return context

    def enroll(self, context: CmpCertificateRequestContext) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Enroll via CMP."""
        return enroll_cmp(context, sender_kid=self.state.get('cmp_sender_kid'))
