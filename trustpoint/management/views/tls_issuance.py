# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""TLS server credential issuance: external EST enrollment and local Issuing CA issuance.

The EST flow is a concrete instantiation of the abstract EST request wizard
(``pki/views/est_request.py``); the local Issuing CA flow issues the credential
directly from a CA hosted in Trustpoint.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView

from crypto.domain.errors import CryptoError
from management.forms import TlsAddRequestCmpForm, TlsAddRequestEstForm, TlsExternalCsrKeyForm, TlsLocalCaSelectForm
from management.views.tls import TlsSettingsContextMixin
from pki.models import CaModel, CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.services.tls_server_issuance import finalize_tls_server_enrollment, issue_tls_server_local
from pki.util.cert_profile import ProfileValidationError
from pki.util.certificate_request import build_cert_content_summary
from pki.views.cmp_request import CmpRequestCertView, CmpRequestView
from pki.views.est_request import (
    CertificateDefineCertContentView,
    CertificateRequestStateMixin,
    CertificateRequestWizardView,
    CertificateTruststoreAssociationView,
    EstRequestCertView,
    EstRequestView,
)
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse

TLS_SCOPE = 'management-tls-issuance'


# ===== External EST enrollment ===============================================


class TlsAddRequestEstView(TlsSettingsContextMixin, EstRequestView):
    """Generate the TLS key and configure the external EST PKI."""

    form_class = TlsAddRequestEstForm
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    key_extractable = True
    truststore_url_name = 'management:tls-truststore-association'


class TlsTruststoreAssociationView(TlsSettingsContextMixin, CertificateTruststoreAssociationView):
    """Associate the trust store used to validate the externally issued TLS certificate."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    content_url_name = 'management:tls-define-cert-content-est'


class TlsDefineCertContentEstView(TlsSettingsContextMixin, CertificateDefineCertContentView):
    """Define the certificate content for the external EST enrollment."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    default_profile_name = 'tls_server'
    profile_credential_type = CertificateProfileModel.ProfileCredentialType.APPLICATION
    request_cert_url_name = 'management:tls-request-cert-est'


class TlsRequestCertEstView(TlsSettingsContextMixin, EstRequestCertView):
    """Review the EST request, then enroll the TLS certificate."""

    template_name = 'management/tls/request_cert_est.html'
    title = 'Request TLS Certificate via EST'
    description = 'Review the request and enroll the TLS server certificate from the external EST PKI.'
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    edit_url_name = 'management:tls-define-cert-content-est'
    request_cert_url_name = 'management:tls-request-cert-est'
    success_url_name = 'management:tls'
    cancel_url_name = 'management:tls'

    def finalize(
        self,
        credential: CredentialModel,
        issued_cert: Any,
        extra_certs: list[Any],
        truststore: Any,
    ) -> Any:
        """Validate and attach the EST-issued TLS server certificate."""
        return finalize_tls_server_enrollment(credential, issued_cert, extra_certs, truststore)


# ===== External CMP enrollment ===============================================


class TlsAddRequestCmpView(TlsSettingsContextMixin, CmpRequestView):
    """Generate the TLS key and configure the external CMP PKI."""

    form_class = TlsAddRequestCmpForm
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    key_extractable = True
    truststore_url_name = 'management:tls-cmp-truststore-association'


class TlsCmpTruststoreAssociationView(TlsSettingsContextMixin, CertificateTruststoreAssociationView):
    """Associate the trust store used to validate the externally issued TLS certificate."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    content_url_name = 'management:tls-define-cert-content-cmp'


class TlsDefineCertContentCmpView(TlsSettingsContextMixin, CertificateDefineCertContentView):
    """Define the certificate content for the external CMP enrollment."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    default_profile_name = 'tls_server'
    profile_credential_type = CertificateProfileModel.ProfileCredentialType.APPLICATION
    request_cert_url_name = 'management:tls-request-cert-cmp'


class TlsRequestCertCmpView(TlsSettingsContextMixin, CmpRequestCertView):
    """Review the CMP request, then enroll the TLS certificate."""

    template_name = 'management/tls/request_cert_cmp.html'
    title = 'Request TLS Certificate via CMP'
    description = 'Review the request and enroll the TLS server certificate from the external PKI via CMP.'
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    edit_url_name = 'management:tls-define-cert-content-cmp'
    request_cert_url_name = 'management:tls-request-cert-cmp'
    success_url_name = 'management:tls'
    cancel_url_name = 'management:tls'

    def finalize(
        self,
        credential: CredentialModel,
        issued_cert: Any,
        extra_certs: list[Any],
        truststore: Any,
    ) -> Any:
        """Validate and attach the CMP-issued TLS server certificate."""
        return finalize_tls_server_enrollment(credential, issued_cert, extra_certs, truststore)


# ===== Local Issuing CA issuance =============================================


class TlsLocalCaKeyView(TlsSettingsContextMixin, CertificateRequestWizardView[TlsExternalCsrKeyForm]):
    """Generate the TLS key pair for the local Issuing CA flow."""

    pending_required = False
    form_class = TlsExternalCsrKeyForm
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    key_extractable = True

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the key-step heading and action label."""
        return super().get_context_data(**kwargs) | {
            'title': _('Generate TLS Key'),
            'description': _('Generate a new keypair in Trustpoint for the TLS server credential.'),
            'section_title': _('Key Type'),
            'section_description': _('Select the cryptographic key type for the new TLS credential.'),
            'submit_label': _('Generate Key'),
        }

    def form_valid(self, form: TlsExternalCsrKeyForm) -> HttpResponse:
        """Create the managed key and proceed to the Issuing CA selection."""
        try:
            credential, scope = self._generate_pending_credential(form.cleaned_data['key_type'])
        except (CryptoError, ValidationError) as exception:
            form.add_error(None, str(exception))
            return self.form_invalid(form)
        self.request.session[f'{TLS_SCOPE}_{credential.pk}'] = {
            'scope': scope,
            'key_type': form.cleaned_data['key_type'],
        }
        return redirect('management:tls-local-ca', pk=credential.pk)


class TlsLocalCaSelectView(TlsSettingsContextMixin, CertificateRequestWizardView[TlsLocalCaSelectForm]):
    """Select a local Issuing CA hosted in Trustpoint."""

    form_class = TlsLocalCaSelectForm
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the Issuing CA selection heading and action label."""
        return super().get_context_data(**kwargs) | {
            'title': _('Select Issuing CA'),
            'description': _('Choose the local Issuing CA that will sign the TLS server credential.'),
            'section_title': _('Issuing CA'),
            'section_description': _('Only active Issuing CAs hosted in Trustpoint are listed.'),
            'submit_label': _('Continue'),
        }

    def form_valid(self, form: TlsLocalCaSelectForm) -> HttpResponse:
        """Store the selected Issuing CA for this credential's session."""
        self.state['ca_pk'] = form.cleaned_data['issuing_ca'].pk
        self.save_state()
        return redirect('management:tls-local-content', pk=self.credential.pk)


class TlsLocalCaContentView(TlsSettingsContextMixin, CertificateDefineCertContentView):
    """Define the certificate content for the local Issuing CA issuance."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    default_profile_name = 'tls_server'
    profile_credential_type = CertificateProfileModel.ProfileCredentialType.APPLICATION
    request_cert_url_name = 'management:tls-local-request'


class TlsLocalCaRequestView(
    TlsSettingsContextMixin, CertificateRequestStateMixin, LoggerMixin, DetailView[CredentialModel]
):
    """Review the local CA request, then issue the TLS certificate."""

    model = CredentialModel
    context_object_name = 'credential'
    template_name = 'management/tls/request_local.html'
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE

    def get_queryset(self) -> QuerySet[CredentialModel, CredentialModel]:
        """Limit requests to pending, unissued TLS server credentials."""
        return CredentialModel.objects.filter(
            certificate__isnull=True,
            credential_type=self.credential_type,
        )

    def get_object(self, queryset: QuerySet[CredentialModel, CredentialModel] | None = None) -> CredentialModel:
        """Load the pending credential and its session state."""
        self._load_state(self.kwargs['pk'])
        return super().get_object(queryset)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the selected Issuing CA and content summary to the review page."""
        content = self.state.get('content')
        return super().get_context_data(**kwargs) | {
            'has_cert_content': bool(content),
            'cert_content_summary': build_cert_content_summary(content) if content else {},
            'edit_url_name': 'management:tls-local-content',
            'issuing_ca': (
                get_object_or_404(CaModel, pk=self.state['ca_pk']) if self.state.get('ca_pk') else None
            ),
        }

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Issue the TLS certificate from the selected local Issuing CA."""
        credential = self.get_object()
        content = self.state.get('content')
        if not content:
            return redirect('management:tls-local-content', pk=credential.pk)
        try:
            profile = get_object_or_404(CertificateProfileModel, pk=self.state.get('profile_pk'))
            issue_tls_server_local(
                credential,
                profile,
                content,
                get_object_or_404(CaModel, pk=self.state['ca_pk']),
            )
        except (ValueError, KeyError, ProfileValidationError, CryptoError):
            self.logger.exception('Failed to issue TLS certificate locally')
            return redirect('management:tls-local-content', pk=credential.pk)
        del request.session[self.session_key]
        return redirect('management:tls')
