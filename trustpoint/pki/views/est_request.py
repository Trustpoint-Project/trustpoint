# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Abstract certificate request wizard, independent of the requested certificate type and protocol.

The steps (request -> trust store -> certificate content -> request) are
identical for every externally issued certificate. Concrete subclasses provide
the certificate type, the profile selection, the enrollment protocol (EST or
CMP) and the finalization step that stores the issued certificate:

- TLS server credential (``management/views/tls_issuance.py``)
- Issuing CA (``pki/views/issuing_cas.py``)
"""

from __future__ import annotations

import abc
import json
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar
from uuid import uuid4

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.forms import Form
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseBase
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.generic import FormView
from django.views.generic.detail import DetailView

from crypto.domain.errors import CryptoError
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from pki.forms import TruststoreAddForm
from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.forms.est_request import CertificateTruststoreAssociationForm
from pki.models import CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import TruststoreModel
from pki.services.est_enrollment import enroll_est
from pki.services.external_csr import external_csr_profile
from pki.services.key_generation import generate_pending_credential
from pki.util.cert_profile import ProfileValidationError
from pki.util.certificate_request import build_cert_content_summary, build_request_data
from pki.views.mixins import CertificateProfileSelectionMixin
from request.clients import EstClientError
from request.request_context import EstCertificateRequestContext
from shared.views import FormErrorMessageMixin
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from cryptography import x509
    from django.db.models import QuerySet

WizardForm = TypeVar('WizardForm', bound=Form)


class CertificateRequestStateMixin:
    """Session-scoped pending-request state shared by all certificate request wizard steps."""

    session_scope: ClassVar[str] = 'cert-request'
    credential_type: CredentialModel.CredentialTypeChoice
    key_extractable: bool = False

    request: HttpRequest
    credential: CredentialModel
    state: dict[str, Any]
    session_key: str

    def _load_state(self, pk: int) -> None:
        self.session_key = f'{self.session_scope}_{pk}'
        self.state = self.request.session.get(self.session_key, {})

    def _resolve_credential(self, pk: int) -> CredentialModel:
        return get_object_or_404(
            CredentialModel,
            pk=pk,
            certificate__isnull=True,
            credential_type=self.credential_type,
            managed_private_key__alias=f'{self.session_scope}/{self.state["scope"]}',
        )

    def save_state(self) -> None:
        """Persist only the current credential's JSON-safe state."""
        self.request.session[self.session_key] = json.loads(json.dumps(self.state, cls=DjangoJSONEncoder))

    def _generate_pending_credential(self, key_type: str) -> tuple[CredentialModel, str]:
        """Generate the managed key for the pending request, returning the credential and its scope."""
        scope = uuid4().hex
        policy = (
            KeyPolicy(extractable=True, signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH)
            if self.key_extractable
            else KeyPolicy.managed_signing_key(
                signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH,
            )
        )
        credential = generate_pending_credential(
            alias=f'{self.session_scope}/{scope}',
            key_type=key_type,
            credential_type=self.credential_type,
            policy=policy,
        )
        return credential, scope


class CertificateRequestWizardView(
    CertificateRequestStateMixin, FormErrorMessageMixin, LoggerMixin, FormView[WizardForm]
):
    """Base for the form-based certificate request steps."""

    template_name = 'pki/certificate_request/config.html'
    pending_required = True

    # URL names (namespaced, set by concrete subclasses).
    truststore_url_name: ClassVar[str] = ''
    content_url_name: ClassVar[str] = ''
    request_cert_url_name: ClassVar[str] = ''
    back_url_name: ClassVar[str] = ''

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Resolve the session-scoped pending credential."""
        if self.pending_required:
            self._load_state(kwargs['pk'])
            if not self.state.get('scope'):
                raise Http404
            self.credential = self._resolve_credential(kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Expose the pending credential and back URL alongside the page context."""
        return super().get_context_data(**kwargs) | {
            'credential': getattr(self, 'credential', None),
            'back_url_name': self.back_url_name,
        }


class CertificateRequestView(CertificateRequestWizardView[Form]):
    """Step 1: generate the key and configure the remote PKI."""

    pending_required = False
    # form_class is provided by the concrete subclass.
    title: ClassVar[str] = 'Request Certificate'
    description: ClassVar[str] = 'Generate a keypair and request the certificate from an external PKI.'
    section_title: ClassVar[str] = 'Request'
    section_description: ClassVar[str] = 'The key type and the external endpoint used for the request.'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the request heading and action label."""
        return super().get_context_data(**kwargs) | {
            'title': self.title,
            'description': self.description,
            'section_title': self.section_title,
            'section_description': self.section_description,
            'submit_label': _('Continue'),
        }

    def form_valid(self, form: Form) -> HttpResponse:
        """Create the managed key and store the connection settings in the session."""
        try:
            credential, scope = self._generate_pending_credential(form.cleaned_data['key_type'])
        except (CryptoError, ValidationError) as exception:
            form.add_error(None, str(exception))
            return self.form_invalid(form)
        self.request.session[f'{self.session_scope}_{credential.pk}'] = {
            'scope': scope,
            **form.cleaned_data,
        }
        return redirect(self.truststore_url_name, pk=credential.pk)


class EstRequestView(CertificateRequestView):
    """Step 1 (EST): generate the key and configure the external EST PKI."""

    title = 'Request Certificate via EST'
    description = 'Generate a keypair and request the certificate from an external EST PKI.'
    section_title = 'EST Request'
    section_description = 'The key type and the external EST endpoint used for the request.'


class CertificateTruststoreAssociationView(CertificateRequestWizardView[CertificateTruststoreAssociationForm]):
    """Step 2: associate the trust store used to validate the issued certificate."""

    form_class = CertificateTruststoreAssociationForm
    template_name = 'pki/certificate_request/truststore_association.html'
    cancel_url_name: ClassVar[str] = ''
    truststore_intended_usage: ClassVar[TruststoreModel.IntendedUsage] = TruststoreModel.IntendedUsage.TLS
    truststore_info_label: ClassVar[str] = 'EST:'
    truststore_info_text: ClassVar[str] = (
        'Select or import the TLS server certificate of the remote PKI. '
        'It is used to secure and validate the HTTPS connection.'
    )

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the configured truststore usage to the association form."""
        return super().get_form_kwargs() | {'truststore_intended_usage': self.truststore_intended_usage}

    def get_initial(self) -> dict[str, Any]:
        """Preselect a previously imported or selected trust store."""
        return {'trust_store': self.request.GET.get('truststore_id') or self.state.get('truststore_pk')}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Include the trust store import form, protocol info, and cancel URL."""
        context = super().get_context_data(**kwargs)
        context.setdefault(
            'import_form',
            TruststoreAddForm(pinned_intended_usage=self.truststore_intended_usage),
        )
        context['cancel_url_name'] = self.cancel_url_name
        context['truststore_info_label'] = self.truststore_info_label
        context['truststore_info_text'] = self.truststore_info_text
        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Route trust store import submissions through the existing import form."""
        if 'trust_store_file' in request.FILES or request.POST.get('import_truststore'):
            import_form = TruststoreAddForm(
                request.POST,
                request.FILES,
                pinned_intended_usage=self.truststore_intended_usage,
            )
            if import_form.is_valid():
                truststore = import_form.cleaned_data['truststore']
                return redirect(
                    reverse(self.truststore_url_name, kwargs={'pk': self.credential.pk})
                    + f'?truststore_id={truststore.pk}'
                )
            return self.render_to_response(self.get_context_data(import_form=import_form))
        return super().post(request, *args, **kwargs)

    def form_valid(self, form: CertificateTruststoreAssociationForm) -> HttpResponse:
        """Store the selected trust store and proceed to content definition."""
        self.state['truststore_pk'] = form.cleaned_data['trust_store'].pk
        self.save_state()
        return redirect(self.content_url_name, pk=self.credential.pk)


class CertificateDefineCertContentView(
    CertificateRequestWizardView[CertificateIssuanceForm], CertificateProfileSelectionMixin
):
    """Step 3: define the certificate content using a certificate profile."""

    template_name = 'pki/certificate_request/content.html'
    form_class = CertificateIssuanceForm
    default_profile_name: ClassVar[str] = ''
    profile_credential_type: str | None = None
    cancel_url_name: ClassVar[str] = ''
    cert_profile: CertificateProfileModel
    available_profiles: list[CertificateProfileModel]

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Resolve the profile, then delegate to the session checks."""
        resolved = self._resolve_cert_profile(request)
        if resolved is None:
            raise Http404(_('No certificate profiles found. Please create one first.'))
        self.cert_profile = resolved
        return super().dispatch(request, *args, **kwargs)

    def _resolve_cert_profile(self, request: HttpRequest) -> CertificateProfileModel | None:
        """Resolve a profile of the configured type, defaulting to ``default_profile_name``."""
        queryset = CertificateProfileModel.objects.all()
        if self.profile_credential_type is not None:
            queryset = queryset.filter(credential_type=self.profile_credential_type)
        profiles = list(queryset.order_by('display_name', 'unique_name'))
        self.available_profiles = profiles
        if not profiles:
            return None
        selected_pk = request.GET.get('cert_profile_pk') or request.POST.get('cert_profile_pk')
        if selected_pk:
            try:
                requested_pk = int(selected_pk)
            except (ValueError, TypeError):
                pass
            else:
                for profile in profiles:
                    if profile.pk == requested_pk:
                        return profile
        return next((profile for profile in profiles if profile.unique_name == self.default_profile_name), profiles[0])

    def get_form_kwargs(self) -> dict[str, Any]:
        """Reuse the profile's standard dynamic certificate-content form."""
        return super().get_form_kwargs() | {'profile': external_csr_profile(self.cert_profile).profile}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Show the available profiles, the selected profile, and the cancel URL."""
        return super().get_context_data(**kwargs) | {
            'title': _('Define Certificate Content'),
            'submit_label': _('Continue'),
            'cert_profile': self.cert_profile,
            'available_profiles': self.available_profiles,
            'cancel_url_name': self.cancel_url_name,
        }

    def form_valid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Store the defined content and proceed to the review step."""
        self.state['content'] = json.loads(json.dumps(form.cleaned_data, cls=DjangoJSONEncoder))
        self.state['profile_pk'] = self.cert_profile.pk
        self.save_state()
        return redirect(self.request_cert_url_name, pk=self.credential.pk)


class CertificateRequestCertView(CertificateRequestStateMixin, LoggerMixin, DetailView[CredentialModel]):
    """Step 4: review the request, then enroll the certificate (protocol-neutral)."""

    model = CredentialModel
    context_object_name = 'credential'
    template_name: str = ''
    title: ClassVar[str] = 'Request Certificate'
    description: ClassVar[str] = 'Review the request and enroll the certificate from the external PKI.'
    allow_ca_certificate_request: bool = False
    client_error_types: ClassVar[tuple[type[Exception], ...]] = ()
    edit_url_name: ClassVar[str] = ''
    request_cert_url_name: ClassVar[str] = ''
    success_url_name: ClassVar[str] = ''
    cancel_url_name: ClassVar[str] = ''

    has_cert_content: bool = False
    cert_content_summary: dict[str, Any]
    state: dict[str, Any]
    session_key: str

    def get_queryset(self) -> QuerySet[CredentialModel, CredentialModel]:
        """Limit requests to pending, unissued credentials."""
        return CredentialModel.objects.filter(
            certificate__isnull=True,
            credential_type=self.credential_type,
        )

    def get_object(self, queryset: QuerySet[CredentialModel, CredentialModel] | None = None) -> CredentialModel:
        """Load the pending credential and its session state."""
        self._load_state(self.kwargs['pk'])
        return super().get_object(queryset)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the defined content summary and the connection details."""
        content = self.state.get('content')
        self.has_cert_content = bool(content)
        self.cert_content_summary = build_cert_content_summary(content) if content else {}
        return super().get_context_data(**kwargs) | {
            'title': self.title,
            'description': self.description,
            'has_cert_content': self.has_cert_content,
            'cert_content_summary': self.cert_content_summary,
            'edit_url_name': self.edit_url_name,
            'cancel_url_name': self.cancel_url_name,
            'remote_host': self.state.get('remote_host'),
            'remote_port': self.state.get('remote_port'),
            'remote_path': self.state.get('remote_path'),
            'truststore': (
                get_object_or_404(TruststoreModel, pk=self.state['truststore_pk'])
                if self.state.get('truststore_pk')
                else None
            ),
        }

    @abc.abstractmethod
    def build_enrollment_context(
        self,
        credential: CredentialModel,
        profile: CertificateProfileModel,
        content: dict[str, Any],
        truststore: TruststoreModel,
    ) -> Any:
        """Build the protocol-specific enrollment context."""

    @abc.abstractmethod
    def enroll(self, context: Any) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Send the request via the concrete protocol and return the issued certificate."""

    @abc.abstractmethod
    def finalize(
        self,
        credential: CredentialModel,
        issued_cert: x509.Certificate,
        extra_certs: list[x509.Certificate],
        truststore: TruststoreModel,
    ) -> Any:
        """Validate and store the issued certificate for the concrete certificate type."""

    def _redirect_after_finalize(self, _result: Any) -> HttpResponse:
        """Return the success redirect after finalization."""
        return redirect(self.success_url_name)

    def build_request_data_for_enrollment(self, content: dict[str, Any]) -> dict[str, Any]:
        """Convert the certificate content into the profile request data."""
        return build_request_data(content, keep_empty_sans=True)

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Enroll the certificate via the configured protocol and finalize it."""
        credential = self.get_object()
        content = self.state.get('content')
        if not content:
            return redirect(self.edit_url_name, pk=credential.pk)
        try:
            profile = get_object_or_404(CertificateProfileModel, pk=self.state.get('profile_pk'))
            truststore = get_object_or_404(TruststoreModel, pk=self.state['truststore_pk'])
            context = self.build_enrollment_context(credential, profile, content, truststore)
            issued_cert, extra_certs = self.enroll(context)
            result = self.finalize(credential, issued_cert, list(extra_certs), truststore)
        except self.client_error_types as exc:
            self.logger.exception('Client error during certificate enrollment')
            messages.error(request, _('Enrollment failed: {error}').format(error=exc))
            return redirect(self.request_cert_url_name, pk=credential.pk)
        except (ValueError, KeyError, ProfileValidationError, CryptoError) as exc:
            self.logger.exception('Failed to enroll certificate')
            messages.error(request, _('The certificate request could not be completed: {error}').format(error=exc))
            return redirect(self.edit_url_name, pk=credential.pk)
        del request.session[self.session_key]
        return self._redirect_after_finalize(result)


class EstRequestCertView(CertificateRequestCertView):
    """Step 4 (EST): review the request, then enroll the certificate via EST."""

    template_name = 'pki/certificate_request/request_cert_est.html'
    title = 'Request Certificate via EST'
    description = 'Review the request and enroll the certificate from the external EST PKI.'
    client_error_types = (EstClientError,)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the EST username to the review page."""
        context = super().get_context_data(**kwargs)
        context['est_username'] = self.state.get('est_username')
        return context

    def build_enrollment_context(
        self,
        credential: CredentialModel,
        profile: CertificateProfileModel,
        content: dict[str, Any],
        truststore: TruststoreModel,
    ) -> EstCertificateRequestContext:
        """Build the EST enrollment context from the stored configuration."""
        context = EstCertificateRequestContext(
            operation='simpleenroll',
            protocol='est',
            domain=None,
            cert_profile_str=profile.unique_name,
            certificate_profile_model=external_csr_profile(profile),
            allow_ca_certificate_request=self.allow_ca_certificate_request,
            est_server_host=self.state['remote_host'],
            est_server_port=self.state['remote_port'],
            est_server_path=self.state['remote_path'],
            est_username=self.state['est_username'],
            est_password=self.state['est_password'],
            est_server_truststore=truststore,
        )
        context.request_data = self.build_request_data_for_enrollment(content)
        context.owner_credential = credential
        return context

    def enroll(self, context: EstCertificateRequestContext) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Enroll via EST."""
        return enroll_est(context)
