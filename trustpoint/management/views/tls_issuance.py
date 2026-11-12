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
from management.forms import TlsAddRequestCmpForm, TlsAddRequestEstForm, TlsLocalCaSelectForm
from management.views.tls import TlsSettingsContextMixin
from pki.key_types import TLS_KEY_TYPE_CHOICES
from pki.models import CaModel, CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import TruststoreModel
from pki.services.management_issuance import key_type_for_management_ca
from pki.services.tls_server_issuance import (
    finalize_tls_server_enrollment,
    issue_tls_server_local,
    issue_tls_server_remote,
)
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
from request.clients import EstClientError
from request.clients.cmp_client import CmpClientError
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
    back_url_name = 'management:tls-add-method_select'


class TlsTruststoreAssociationView(TlsSettingsContextMixin, CertificateTruststoreAssociationView):
    """Associate the trust store used to validate the externally issued TLS certificate."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    content_url_name = 'management:tls-define-cert-content-est'
    cancel_url_name = 'management:tls'


class TlsDefineCertContentEstView(TlsSettingsContextMixin, CertificateDefineCertContentView):
    """Define the certificate content for the external EST enrollment."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    default_profile_name = 'tls_server'
    profile_credential_type = CertificateProfileModel.ProfileCredentialType.APPLICATION
    request_cert_url_name = 'management:tls-request-cert-est'
    cancel_url_name = 'management:tls'


class TlsRequestCertEstView(TlsSettingsContextMixin, EstRequestCertView):
    """Review the EST request, then enroll the TLS certificate."""

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
    back_url_name = 'management:tls-add-method_select'


class TlsCmpTruststoreAssociationView(TlsSettingsContextMixin, CertificateTruststoreAssociationView):
    """Associate the trust store used to validate the externally issued TLS certificate."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    content_url_name = 'management:tls-define-cert-content-cmp'
    cancel_url_name = 'management:tls'
    truststore_intended_usage = TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
    truststore_info_label = 'CMP:'
    truststore_info_text = (
        'Select or import the Issuing CA certificate of the remote PKI. '
        'It is used to identify the recipient CA and verify CMP responses.'
    )


class TlsDefineCertContentCmpView(TlsSettingsContextMixin, CertificateDefineCertContentView):
    """Define the certificate content for the external CMP enrollment."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    default_profile_name = 'tls_server'
    profile_credential_type = CertificateProfileModel.ProfileCredentialType.APPLICATION
    request_cert_url_name = 'management:tls-request-cert-cmp'
    cancel_url_name = 'management:tls'


class TlsRequestCertCmpView(TlsSettingsContextMixin, CmpRequestCertView):
    """Review the CMP request, then enroll the TLS certificate."""

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


# ===== Management CA issuance ================================================


class TlsLocalCaKeyView(TlsSettingsContextMixin, CertificateRequestWizardView[TlsLocalCaSelectForm]):
    """Select the management CA and create the keypair for TLS certificate issuance."""

    pending_required = False
    form_class = TlsLocalCaSelectForm
    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    key_extractable = True
    back_url_name = 'management:tls-add-method_select'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the CA selection heading."""
        return super().get_context_data(**kwargs) | {
            'title': _('Select Management CA'),
            'description': _('Choose the management CA that will issue the TLS server certificate.'),
            'section_title': _('Management CA'),
            'section_description': _(
                'The TLS key type is bound to the selected management CA. '
                'Internal CAs sign the certificate in Trustpoint; external CAs forward the request to their PKI.'
            ),
            'submit_label': _('Continue'),
        }

    def form_valid(self, form: TlsLocalCaSelectForm) -> HttpResponse:
        """Create the managed key and proceed to certificate content definition."""
        try:
            key_type = key_type_for_management_ca(form.cleaned_data['issuing_ca'], TLS_KEY_TYPE_CHOICES)
            credential, scope = self._generate_pending_credential(key_type)
        except ValidationError as exception:
            form.add_error(None, exception)
            return self.form_invalid(form)
        except CryptoError as exception:
            form.add_error(None, str(exception))
            return self.form_invalid(form)
        self.request.session[f'{TLS_SCOPE}_{credential.pk}'] = {
            'scope': scope,
            'key_type': key_type,
            'ca_pk': form.cleaned_data['issuing_ca'].pk,
        }
        return redirect('management:tls-local-content', pk=credential.pk)


class TlsLocalCaContentView(TlsSettingsContextMixin, CertificateDefineCertContentView):
    """Define the certificate content for the selected management CA issuance."""

    credential_type = CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER
    session_scope = TLS_SCOPE
    default_profile_name = 'tls_server'
    profile_credential_type = CertificateProfileModel.ProfileCredentialType.APPLICATION
    request_cert_url_name = 'management:tls-local-request'
    cancel_url_name = 'management:tls'


class TlsLocalCaRequestView(
    TlsSettingsContextMixin, CertificateRequestStateMixin, LoggerMixin, DetailView[CredentialModel]
):
    """Review the request, then issue it locally or request it from the external management CA."""

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
        """Add the selected management CA and content summary to the review page."""
        content = self.state.get('content')
        issuing_ca = get_object_or_404(CaModel, pk=self.state['ca_pk']) if self.state.get('ca_pk') else None
        return super().get_context_data(**kwargs) | {
            'has_cert_content': bool(content),
            'cert_content_summary': build_cert_content_summary(content) if content else {},
            'edit_url_name': 'management:tls-local-content',
            'issuing_ca': issuing_ca,
            'remote_issuance': bool(issuing_ca and not issuing_ca.is_issuing_ca),
        }

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Issue locally with an internal CA or request the certificate from an external CA."""
        credential = self.get_object()
        content = self.state.get('content')
        if not content:
            return redirect('management:tls-local-content', pk=credential.pk)
        try:
            profile = get_object_or_404(CertificateProfileModel, pk=self.state.get('profile_pk'))
            issuing_ca = get_object_or_404(CaModel, pk=self.state['ca_pk'])
            if issuing_ca.is_issuing_ca:
                issue_tls_server_local(credential, profile, content, issuing_ca)
            else:
                issue_tls_server_remote(credential, profile, content, issuing_ca)
        except (ValueError, KeyError, ProfileValidationError, CryptoError, EstClientError, CmpClientError):
            self.logger.exception('Failed to issue TLS certificate from the management CA')
            return redirect('management:tls-local-content', pk=credential.pk)
        del request.session[self.session_key]
        return redirect('management:tls')
