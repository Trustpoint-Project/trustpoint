"""Session-scoped external PKI wizard for management TLS certificates."""

from __future__ import annotations

import json
from typing import Any, TypeVar, cast
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.forms import Form
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import FormView

from crypto.domain.errors import CryptoError
from crypto.domain.policies import KeyPolicy, SigningExecutionMode
from management.forms import (
    TlsExternalCsrCertificateForm,
    TlsExternalCsrKeyForm,
    TlsExternalCsrTruststoreForm,
)
from pki.forms import CertificateIssuanceForm, TruststoreAddForm
from pki.models import CredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import TruststoreModel
from pki.services.external_csr import build_external_csr, csr_download_response, finalize_external_certificate
from pki.services.key_generation import generate_pending_credential
from pki.util.cert_profile import ProfileValidationError
from users.permissions import AppPermissions

TLS_CSR_SCOPE = 'management-tls-external-csr'
WizardForm = TypeVar('WizardForm', bound=Form)


class TlsExternalCsrWizardView(FormView[WizardForm]):
    """Enforce permission and session ownership before every wizard operation."""

    template_name = 'management/tls/external_csr_form.html'
    pending_required = True
    credential: CredentialModel
    state: dict[str, Any]
    session_key: str

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Reject foreign sessions and completed credentials before processing data."""
        if not request.user.has_perm(AppPermissions.MANAGE_TLS_WEBSERVER_CONFIGURATION):
            raise PermissionDenied
        if self.pending_required:
            self.session_key = f'tls_external_csr_{kwargs["pk"]}'
            self.state = request.session.get(self.session_key, {})
            scope = self.state.get('scope')
            if not scope:
                raise Http404
            self.credential = get_object_or_404(
                CredentialModel, pk=kwargs['pk'], certificate__isnull=True,
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
                managed_private_key__alias=f'{TLS_CSR_SCOPE}/{scope}',
            )
        return cast('HttpResponse', super().dispatch(request, *args, **kwargs))

    def save_state(self) -> None:
        """Persist only the current credential's JSON-safe state."""
        self.request.session[self.session_key] = json.loads(json.dumps(self.state, cls=DjangoJSONEncoder))

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Apply the existing TLS navigation context."""
        return super().get_context_data(**kwargs) | {
            'page_category': 'management', 'page_name': 'tls',
            'credential': getattr(self, 'credential', None),
        }


class TlsExternalCsrKeyView(TlsExternalCsrWizardView[TlsExternalCsrKeyForm]):
    """Immediately create one key-only TLS credential."""

    pending_required = False
    template_name = 'management/tls/external_csr_key.html'
    form_class = TlsExternalCsrKeyForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Describe the key-generation step."""
        return super().get_context_data(**kwargs) | {
            'title': _('Generate TLS Key'), 'submit_label': _('Generate Key'),
        }

    def form_valid(self, form: TlsExternalCsrKeyForm) -> HttpResponse:
        """Create the managed key with the deployment policy, without exporting it."""
        scope = uuid4().hex
        try:
            credential = generate_pending_credential(
                alias=f'{TLS_CSR_SCOPE}/{scope}', key_type=form.cleaned_data['key_type'],
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
                policy=KeyPolicy(extractable=True, signing_execution_mode=SigningExecutionMode.ALLOW_APPLICATION_HASH),
            )
        except (CryptoError, ValidationError) as exception:
            form.add_error(None, str(exception))
            return self.form_invalid(form)
        self.request.session[f'tls_external_csr_{credential.pk}'] = {
            'scope': scope, 'key_type': form.cleaned_data['key_type'],
        }
        return redirect('management:tls-external-csr-truststore', pk=credential.pk)


class TlsExternalCsrTruststoreView(TlsExternalCsrWizardView[TlsExternalCsrTruststoreForm]):
    """Select or import the external PKI chain using the existing import form."""

    form_class = TlsExternalCsrTruststoreForm

    def get_initial(self) -> dict[str, Any]:
        """Preselect a newly imported or previously selected truststore."""
        return {'truststore': self.request.GET.get('truststore_id') or self.state.get('truststore_pk')}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Include the truststore import modal."""
        context = super().get_context_data(**kwargs)
        context.setdefault(
            'import_form', TruststoreAddForm(initial={'intended_usage': TruststoreModel.IntendedUsage.TLS}),
        )
        return context | {'title': _('Associate Trust Store'), 'submit_label': _('Associate Trust Store')}

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Route modal submissions through the existing truststore import service."""
        if 'trust_store_file' in request.FILES or request.POST.get('import_truststore'):
            import_form = TruststoreAddForm(request.POST, request.FILES)
            if import_form.is_valid():
                truststore = import_form.cleaned_data['truststore']
                return redirect(
                    reverse('management:tls-external-csr-truststore', kwargs={'pk': self.credential.pk})
                    + f'?truststore_id={truststore.pk}'
                )
            return self.render_to_response(self.get_context_data(import_form=import_form))
        return super().post(request, *args, **kwargs)

    def form_valid(self, form: TlsExternalCsrTruststoreForm) -> HttpResponse:
        """Store the selection only in this credential's session namespace."""
        self.state['truststore_pk'] = form.cleaned_data['truststore'].pk
        self.save_state()
        return redirect('management:tls-external-csr-content', pk=self.credential.pk)


class TlsExternalCsrContentView(TlsExternalCsrWizardView[CertificateIssuanceForm]):
    """Define subject and SANs using an APPLICATION certificate profile."""

    form_class = CertificateIssuanceForm
    profile: CertificateProfileModel

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Resolve explicit profiles without silently accepting non-application profiles."""
        if not request.user.has_perm(AppPermissions.MANAGE_TLS_WEBSERVER_CONFIGURATION):
            raise PermissionDenied
        profiles = CertificateProfileModel.objects.filter(
            credential_type=CertificateProfileModel.ProfileCredentialType.APPLICATION,
        )
        selected = request.GET.get('cert_profile_pk') or request.POST.get('cert_profile_pk')
        if selected:
            try:
                self.profile = get_object_or_404(profiles, pk=int(selected))
            except (ValueError, TypeError) as exception:
                raise Http404 from exception
        else:
            self.profile = get_object_or_404(profiles, unique_name='tls_server')
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Reuse the profile's standard dynamic certificate-content form."""
        return super().get_form_kwargs() | {'profile': self.profile.profile}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Show only application profiles and the TLS Server default label."""
        return super().get_context_data(**kwargs) | {
            'title': _('Define TLS Certificate Content'), 'submit_label': _('Generate CSR'),
            'cert_profile': self.profile,
            'available_profiles': CertificateProfileModel.objects.filter(
                credential_type=CertificateProfileModel.ProfileCredentialType.APPLICATION,
            ).order_by('display_name', 'unique_name'),
        }

    def form_valid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Validate the profile request and save the exact CSR before showing it."""
        if not self.state.get('truststore_pk'):
            return redirect('management:tls-external-csr-truststore', pk=self.credential.pk)
        content = json.loads(json.dumps(form.cleaned_data, cls=DjangoJSONEncoder))
        try:
            csr = build_external_csr(self.credential, self.profile, content)
        except (ValueError, ProfileValidationError, CryptoError) as exception:
            form.add_error(None, str(exception))
            return self.form_invalid(form)
        self.state.update({
            'profile_pk': self.profile.pk, 'content': content,
            'csr_pem': csr.public_bytes(Encoding.PEM).decode('ascii'),
        })
        self.save_state()
        return redirect('management:tls-external-csr', pk=self.credential.pk)


class TlsExternalCsrView(TlsExternalCsrWizardView[TlsExternalCsrCertificateForm]):
    """Display/download the CSR and accept its issued certificate on the same page."""

    template_name = 'management/tls/external_csr.html'
    form_class = TlsExternalCsrCertificateForm

    def get_csr(self) -> x509.CertificateSigningRequest:
        """Read the exact session CSR rather than signing a fresh request on every GET."""
        try:
            return x509.load_pem_x509_csr(self.state['csr_pem'].encode('ascii'))
        except (KeyError, ValueError) as exception:
            raise Http404 from exception

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind the upload form to the same key, request identity, and truststore."""
        return super().get_form_kwargs() | {
            'credential': self.credential, 'csr': self.get_csr(),
            'truststore': get_object_or_404(TruststoreModel, pk=self.state.get('truststore_pk')),
        }

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Serve a permission-protected CSR attachment from this same wizard page."""
        if request.GET.get('download') == '1':
            return csr_download_response(self.get_csr(), f'tls-{self.credential.pk}')
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Expose the key, profile, and complete requested identity in the overview."""
        csr = self.get_csr()
        return super().get_context_data(**kwargs) | {
            'csr_pem': self.state['csr_pem'], 'subject': csr.subject.rfc4514_string(),
            'sans': TlsExternalCsrCertificateForm.san_names(csr),
            'key_type': self.state['key_type'],
            'cert_profile': get_object_or_404(CertificateProfileModel, pk=self.state.get('profile_pk')),
        }

    def form_valid(self, form: TlsExternalCsrCertificateForm) -> HttpResponse:
        """Finalize the same credential, leave activation unchanged, and clear only its state."""
        try:
            finalize_external_certificate(self.credential, form.cleaned_data['certificate'], form.chain)
        except ValidationError as exception:
            form.add_error(None, exception)
            return self.form_invalid(form)
        del self.request.session[self.session_key]
        return redirect('management:tls')
