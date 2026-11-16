# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management views for Traceability Credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.utils.translation import gettext_lazy as _
from django.views.generic import DetailView, FormView, ListView, TemplateView

from crypto.domain.errors import CryptoError
from management.models.audit_log import AuditLog
from management.models.traceability import TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCredentialService
from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.models import CaModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.truststore import TruststoreModel
from pki.services import credential_upload as uploads
from pki.services.external_csr import csr_download_response, parse_single_certificate
from pki.services.management_issuance import available_management_cas
from pki.util.cert_profile import ProfileValidationError
from request.clients import EstClientError
from request.clients.cmp_client import CmpClientError
from trustpoint.views.base import ContextDataMixin, UserPermissionRequiredMixin
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from django.db import models
    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse, HttpResponseBase


class TraceabilityCredentialContextMixin(ContextDataMixin):
    """Provide management navigation context."""

    context_page_category = 'management'
    context_page_name = 'traceability_credentials'


class TraceabilityCredentialSettingsForm(forms.Form):
    """Configure an identity using the method selected on the card page."""

    name = forms.CharField(label=_('Name'), max_length=255, widget=forms.TextInput(attrs={'class': 'form-control'}))
    description = forms.CharField(
        label=_('Description'),
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
    )
    management_ca = forms.ModelChoiceField(
        queryset=CaModel.objects.none(),
        label=_('Management CA / RA'),
        help_text=_('The signing key uses the same curve as the selected CA (P-256 or P-384).'),
    )
    curve = forms.ChoiceField(
        label=_('Signing key curve'),
        choices=TraceabilityCredentialModel.Curve.choices,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    def __init__(self, *args: Any, assignment_method: str, **kwargs: Any) -> None:
        """Show only the settings needed by the selected assignment method."""
        super().__init__(*args, **kwargs)
        self.assignment_method = assignment_method
        if assignment_method == TraceabilityCredentialModel.AssignmentMethod.MANAGEMENT_CA:
            cast('forms.ModelChoiceField[CaModel]', self.fields['management_ca']).queryset = available_management_cas()
        else:
            del self.fields['management_ca']
        if assignment_method != TraceabilityCredentialModel.AssignmentMethod.CSR:
            del self.fields['curve']

    def clean(self) -> dict[str, Any]:
        """Bind configuration to the chosen method and validate the CA's curve."""
        data = super().clean() or {}
        data['assignment_method'] = self.assignment_method
        data['management_ca'] = data.get('management_ca')
        data['curve'] = data.get('curve', '')
        if data['management_ca'] is not None:
            try:
                data['curve'] = TraceabilityCredentialService.management_ca_curve(data['management_ca'])
            except ValidationError as error:
                self.add_error('management_ca', error)
        return data

    def clean_name(self) -> str:
        """Reject duplicate names before key generation."""
        name = cast('str', self.cleaned_data['name'])
        if TraceabilityCredentialModel.objects.filter(name=name).exists():
            raise forms.ValidationError(_('A Traceability Credential with this name already exists.'))
        return name


class TraceabilityCredentialDescriptionForm(forms.Form):
    """Validate description edits."""

    description = forms.CharField(
        label=_('Description'),
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
    )


class TraceabilityCertificateForm(CertificateIssuanceForm):
    """Certificate-profile form restricted to the canonical built-in profile."""

    def __init__(self, *args: Any, credential_name: str, **kwargs: Any) -> None:
        """Initialize the form from the canonical profile and prefill its CN."""
        profile = CertificateProfileModel.objects.get(
            unique_name='traceability_credential',
            credential_type=CertificateProfileModel.ProfileCredentialType.EVIDENCE_SIGNING_CREDENTIAL,
        ).profile
        super().__init__(profile, *args, **kwargs)
        if 'common_name' in self.fields:
            self.fields['common_name'].initial = credential_name


class TraceabilityCredentialListView(
    LoginRequiredMixin,
    TraceabilityCredentialContextMixin,
    ListView[TraceabilityCredentialModel],
):
    """List logical Traceability Credentials."""

    model = TraceabilityCredentialModel
    template_name = 'management/traceability_credential/list.html'
    context_object_name = 'credentials'
    paginate_by = 25


class TraceabilityCredentialDetailView(
    LoginRequiredMixin,
    TraceabilityCredentialContextMixin,
    DetailView[TraceabilityCredentialModel],
):
    """Display a credential and its immutable generation history."""

    model = TraceabilityCredentialModel
    template_name = 'management/traceability_credential/detail.html'
    context_object_name = 'credential'

    def get_queryset(self) -> QuerySet[TraceabilityCredentialModel]:
        """Fetch generations and certificate metadata for the detail page."""
        return TraceabilityCredentialModel.objects.select_related(
            'current_generation__credential__certificate'
        ).prefetch_related('generations__credential__certificate')


class TraceabilityCredentialCreateView(
    UserPermissionRequiredMixin,
    TraceabilityCredentialContextMixin,
    TemplateView,
):
    """Choose an assignment method before configuring a signing identity."""

    template_name = 'management/traceability_credential/method_select.html'
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS


class TraceabilityCredentialConfigureView(
    UserPermissionRequiredMixin,
    TraceabilityCredentialContextMixin,
    FormView[TraceabilityCredentialSettingsForm],
):
    """Create a Traceability Credential through the lifecycle service."""

    form_class = TraceabilityCredentialSettingsForm
    template_name = 'management/traceability_credential/form.html'
    extra_context: dict[str, Any] = {  # noqa: RUF012 - Django defines this as an instance attribute.
        'form_title': _('Create Traceability Credential'),
        'form_description': _('Choose how this signing identity receives its initial and replacement credentials.'),
        'submit_label': _('Continue'),
    }
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Accept only one of the four supported card selections."""
        if kwargs['method'] not in TraceabilityCredentialModel.AssignmentMethod.values:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Keep the chosen method bound to the route, including on validation errors."""
        return super().get_form_kwargs() | {'assignment_method': self.kwargs['method']}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Name the selected method and allow returning to method selection."""
        method = TraceabilityCredentialModel.AssignmentMethod(self.kwargs['method'])
        return super().get_context_data(**kwargs) | {
            'form_title': method.label,
            'form_description': _('Configure the signing identity, then continue to certificate assignment.'),
            'select_assignment_method': True,
        }

    def form_valid(self, form: TraceabilityCredentialSettingsForm) -> HttpResponse:
        """Persist configuration before requesting the first signing generation."""
        try:
            credential = TraceabilityCredentialService.configure(**form.cleaned_data)
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)
        self._audit(AuditLog.OperationType.MODEL_CREATED, credential, 'configured')
        return redirect('management:traceability_credential_rotate', pk=credential.pk)

    def _audit(self, operation: str, credential: TraceabilityCredentialModel, action: str) -> None:
        """Write a non-secret lifecycle audit event."""
        AuditLog.create_entry(
            operation_type=operation,
            target=credential,
            target_display=f'Traceability Credential: {credential.name}',
            actor=cast('models.Model', self.request.user),
            details={'action': action},
        )


class TraceabilityCredentialUploadForm(forms.Form):
    """Parse bounded credential files without storing secrets in the session."""

    password = forms.CharField(label=_('File password'), required=False, widget=forms.PasswordInput)

    def __init__(self, *args: Any, method: str, **kwargs: Any) -> None:
        """Show only the files required for the saved assignment method."""
        super().__init__(*args, **kwargs)
        self.method = method
        if method == TraceabilityCredentialModel.AssignmentMethod.PKCS12:
            self.fields['pkcs12'] = forms.FileField(label=_('PKCS#12 file'))
        else:
            self.fields['private_key'] = forms.FileField(label=_('Private key'))
            self.fields['certificate'] = forms.FileField(label=_('Certificate'))
            self.fields['chain'] = forms.FileField(label=_('Certificate chain'), required=False)

    def clean(self) -> dict[str, Any]:
        """Decode each upload using the shared limits and parsers."""
        data = super().clean() or {}
        if self.errors:
            return data
        try:
            password = uploads.encode_upload_password(data['password'])
            if self.method == TraceabilityCredentialModel.AssignmentMethod.PKCS12:
                parsed = uploads.parse_pkcs12(
                    uploads.read_credential_upload(
                        data['pkcs12'],
                        kind=uploads.CredentialFileKind.PKCS12,
                    ),
                    password,
                )
                key, certificate = parsed.private_key, parsed.certificate
                chain = list(parsed.additional_certificates)
            else:
                key = uploads.parse_private_key(
                    uploads.read_credential_upload(
                        data['private_key'],
                        kind=uploads.CredentialFileKind.PRIVATE_KEY,
                    ),
                    password,
                ).as_crypto()
                certificate = uploads.parse_certificate(
                    uploads.read_credential_upload(
                        data['certificate'],
                        kind=uploads.CredentialFileKind.CERTIFICATE,
                    )
                ).as_crypto()
                chain = (
                    list(
                        uploads.parse_certificate_chain(
                            uploads.read_credential_upload(
                                data['chain'],
                                kind=uploads.CredentialFileKind.CHAIN,
                            )
                        ).as_crypto()
                    )
                    if data.get('chain')
                    else []
                )
        except uploads.CredentialUploadError as error:
            raise forms.ValidationError(
                _('Unable to read credential files; check their format, size and password.')
            ) from error
        if not isinstance(key, ec.EllipticCurvePrivateKey) or certificate is None:
            raise forms.ValidationError(_('An EC private key and certificate are required.'))
        data.update(private_key=key, certificate=certificate, chain=chain)
        return data


class TraceabilityCsrCertificateForm(forms.Form):
    """Accept one issued certificate and explicit CA trust anchors."""

    certificate = forms.FileField(label=_('Issued certificate'))
    truststore = forms.ModelChoiceField(queryset=TruststoreModel.objects.all(), label=_('Issuing CA trust store'))

    def clean_certificate(self) -> x509.Certificate:
        """Parse a bounded, single leaf certificate."""
        try:
            return parse_single_certificate(
                uploads.read_credential_upload(
                    self.cleaned_data['certificate'],
                    kind=uploads.CredentialFileKind.CERTIFICATE,
                )
            )
        except uploads.CredentialUploadError as error:
            raise forms.ValidationError(_('Unable to read the issued certificate (maximum 64 KiB).')) from error


class TraceabilityCredentialEditView(
    UserPermissionRequiredMixin,
    TraceabilityCredentialContextMixin,
    FormView[TraceabilityCredentialDescriptionForm],
):
    """Edit only the mutable description field."""

    form_class = TraceabilityCredentialDescriptionForm
    template_name = 'management/traceability_credential/form.html'
    extra_context: dict[str, Any] = {  # noqa: RUF012 - Django defines this as an instance attribute.
        'form_title': _('Edit credential description'),
        'form_description': _('Update the description of this signing identity.'),
        'submit_label': _('Save Changes'),
    }
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Load the logical credential before form processing."""
        self.credential = get_object_or_404(TraceabilityCredentialModel, pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self) -> dict[str, str]:
        """Prefill the current description."""
        return {'description': self.credential.description}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Keep navigation tied to the credential being edited."""
        context = super().get_context_data(**kwargs)
        context['credential'] = self.credential
        return context

    def form_valid(self, form: TraceabilityCredentialDescriptionForm) -> HttpResponse:
        """Delegate the metadata mutation to the service."""
        credential = TraceabilityCredentialService.update_description(self.credential, form.cleaned_data['description'])
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.MODEL_UPDATED,
            target=credential,
            target_display=f'Traceability Credential: {credential.name}',
            actor=cast('models.Model', self.request.user),
            details={'action': 'description_changed'},
        )
        messages.success(self.request, _('Traceability Credential updated successfully.'))
        return redirect('management:traceability_credential_detail', pk=credential.pk)


class TraceabilityCredentialRotateView(
    UserPermissionRequiredMixin,
    TraceabilityCredentialContextMixin,
    FormView[forms.Form],
):
    """Provision a fresh generation using the identity's saved assignment method."""

    template_name = 'management/traceability_credential/form.html'
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Resolve the identity for initial assignment and subsequent rotation."""
        self.credential = get_object_or_404(TraceabilityCredentialModel, pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self) -> type[forms.Form]:
        """Use the saved import method or the canonical certificate profile."""
        if self.credential.pending_credential_id:
            return TraceabilityCsrCertificateForm
        if self.credential.assignment_method in (
            self.credential.AssignmentMethod.PKCS12,
            self.credential.AssignmentMethod.SEPARATE_FILES,
        ):
            return TraceabilityCredentialUploadForm
        return TraceabilityCertificateForm

    def get_form_kwargs(self) -> dict[str, Any]:
        """Bind the selected form to the persisted configuration."""
        kwargs = super().get_form_kwargs()
        if self.get_form_class() == TraceabilityCertificateForm:
            kwargs['credential_name'] = self.credential.name
        elif self.get_form_class() == TraceabilityCredentialUploadForm:
            kwargs['method'] = self.credential.assignment_method
        return kwargs

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Download the exact persisted CSR without generating another key."""
        if request.GET.get('download') == '1' and self.credential.pending_csr:
            return csr_download_response(
                x509.load_pem_x509_csr(self.credential.pending_csr.encode('ascii')),
                f'traceability-{self.credential.pk}',
            )
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Explain activation timing and show the pending CSR when applicable."""
        return super().get_context_data(**kwargs) | {
            'credential': self.credential,
            'form_title': _('Rotate key and certificate'),
            'form_description': _(
                'The replacement must use a new key and certificate. '
                'The current generation retires only after the replacement has been validated.'
            ),
            'submit_label': _('Complete CSR') if self.credential.pending_csr else _('Request new credential'),
            'csr_pem': self.credential.pending_csr,
        }

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Allow cancellation without requiring a certificate upload."""
        if request.POST.get('cancel_csr') and self.credential.pending_credential_id:
            TraceabilityCredentialService.cancel_csr(self.credential)
            self._audit('csr_cancelled')
            return redirect('management:traceability_credential_detail', pk=self.credential.pk)
        return super().post(request, *args, **kwargs)

    def _audit(self, action: str) -> None:
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.MODEL_UPDATED,
            target=self.credential,
            target_display=f'Traceability Credential: {self.credential.name}',
            actor=cast('models.Model', self.request.user),
            details={'action': action},
        )

    def form_valid(self, form: forms.Form) -> HttpResponse:
        """Activate only a validated replacement; leave the old generation intact on failure."""
        try:
            if isinstance(form, TraceabilityCredentialUploadForm):
                TraceabilityCredentialService.import_credential(
                    self.credential,
                    private_key=form.cleaned_data['private_key'],
                    certificate=form.cleaned_data['certificate'],
                    chain=form.cleaned_data['chain'],
                )
            elif isinstance(form, TraceabilityCsrCertificateForm):
                TraceabilityCredentialService.complete_csr(
                    self.credential,
                    certificate=form.cleaned_data['certificate'],
                    truststore=form.cleaned_data['truststore'],
                )
            else:
                result = TraceabilityCredentialService.request_credential(self.credential, content=form.cleaned_data)
                if isinstance(result, str):
                    self._audit('csr_requested')
                    return redirect('management:traceability_credential_rotate', pk=self.credential.pk)
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)
        except (ValueError, CryptoError, ProfileValidationError, EstClientError, CmpClientError):
            form.add_error(
                None, _('Unable to provision the credential. Check the CA and crypto backend configuration.')
            )
            return self.form_invalid(form)
        self._audit('credential_assigned')
        messages.success(self.request, _('Traceability Credential assigned successfully.'))
        return redirect('management:traceability_credential_detail', pk=self.credential.pk)


class TraceabilityCredentialRetireView(
    UserPermissionRequiredMixin,
    TraceabilityCredentialContextMixin,
    FormView[forms.Form],
):
    """Retire a Traceability Credential irreversibly after confirmation."""

    form_class = forms.Form
    template_name = 'management/traceability_credential/confirm_action.html'
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Load the credential without requiring certificate configuration."""
        self.credential = get_object_or_404(TraceabilityCredentialModel, pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Expose the credential being retired."""
        context = super().get_context_data(**kwargs)
        context['credential'] = self.credential
        return context

    def form_valid(self, form: forms.Form) -> HttpResponse:
        """Delegate retirement and preserve the final generation reference."""
        try:
            TraceabilityCredentialService.retire(self.credential)
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.MODEL_UPDATED,
            target=self.credential,
            target_display=f'Traceability Credential: {self.credential.name}',
            actor=cast('models.Model', self.request.user),
            details={'action': 'retired'},
        )
        messages.success(self.request, _('Traceability Credential retired successfully.'))
        return redirect('management:traceability_credential_detail', pk=self.credential.pk)
