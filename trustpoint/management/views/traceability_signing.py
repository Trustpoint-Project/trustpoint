# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management views for Traceability Credentials."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any, cast

from cryptography import x509
from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import DetailView, FormView, ListView

from management.models.audit_log import AuditLog
from management.models.traceability import TraceabilityCredentialModel
from management.services.traceability_signing import TraceabilityCertificateData, TraceabilityCredentialService
from pki.forms.cert_profiles import CertificateIssuanceForm
from pki.models.cert_profile import CertificateProfileModel
from trustpoint.views.base import ContextDataMixin, UserPermissionRequiredMixin
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from django.db import models
    from django.db.models import QuerySet
    from django.http import HttpRequest, HttpResponse


class TraceabilityCredentialContextMixin(ContextDataMixin):
    """Provide management navigation context."""

    context_page_category = 'management'
    context_page_name = 'traceability_credentials'


class TraceabilityCredentialSettingsForm(forms.Form):
    """Validate logical Traceability Credential settings."""

    name = forms.CharField(label=_('Name'), max_length=255, widget=forms.TextInput(attrs={'class': 'form-control'}))
    description = forms.CharField(
        label=_('Description'),
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
    )
    curve = forms.ChoiceField(
        label=_('Curve'),
        choices=TraceabilityCredentialModel.Curve.choices,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    purposes = forms.MultipleChoiceField(
        label=_('Purposes'),
        choices=TraceabilityCredentialModel.Purpose.choices,
        required=True,
        widget=forms.CheckboxSelectMultiple,
    )

    def clean_name(self) -> str:
        """Reject duplicate names before key generation."""
        name = cast('str', self.cleaned_data['name'])
        if TraceabilityCredentialModel.objects.filter(name=name).exists():
            raise forms.ValidationError(_('An Traceability Credential with this name already exists.'))
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
    FormView[TraceabilityCredentialSettingsForm],
):
    """Create an Traceability Credential through the lifecycle service."""

    form_class = TraceabilityCredentialSettingsForm
    template_name = 'management/traceability_credential/form.html'
    success_url = reverse_lazy('management:traceability_credentials')
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS
    def form_valid(self, form: TraceabilityCredentialSettingsForm) -> HttpResponse:
        """Keep logical settings in the session until certificate configuration completes."""
        self.request.session['traceability_signing_settings'] = {
            'name': form.cleaned_data['name'],
            'description': form.cleaned_data['description'],
            'curve': form.cleaned_data['curve'],
            'purposes': form.cleaned_data['purposes'],
        }
        return redirect('management:traceability_credential_certificate')

    def _audit(self, operation: str, credential: TraceabilityCredentialModel, action: str) -> None:
        """Write a non-secret lifecycle audit event."""
        AuditLog.create_entry(
            operation_type=operation,
            target=credential,
            target_display=f'Traceability Credential: {credential.name}',
            actor=cast('models.Model', self.request.user),
            details={'action': action},
        )


class TraceabilityCredentialCertificateView(
    UserPermissionRequiredMixin,
    TraceabilityCredentialContextMixin,
    FormView[TraceabilityCertificateForm],
):
    """Collect certificate values using the canonical profile before creation."""

    form_class = TraceabilityCertificateForm
    template_name = 'management/traceability_credential/form.html'
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Require the first-step settings in the session."""
        if 'traceability_signing_settings' not in request.session:
            return redirect('management:traceability_credential_create')
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the first-step name to the profile form."""
        kwargs = super().get_form_kwargs()
        kwargs['credential_name'] = self.request.session['traceability_signing_settings']['name']
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Set the certificate configuration page title."""
        context = super().get_context_data(**kwargs)
        context['form_title'] = _('Configure Traceability Credential certificate')
        return context

    def form_valid(self, form: TraceabilityCertificateForm) -> HttpResponse:
        """Create only after the profile form has validated certificate values."""
        settings = self.request.session.pop('traceability_signing_settings')
        builder = form.get_certificate_builder()
        now = datetime.datetime.now(datetime.UTC)
        try:
            credential = TraceabilityCredentialService.create(
                name=settings['name'],
                description=settings['description'],
                curve=TraceabilityCredentialModel.Curve(settings['curve']),
                purposes=[TraceabilityCredentialModel.Purpose(purpose) for purpose in settings['purposes']],
                certificate_data=TraceabilityCertificateData(
                    subject=x509.Name([]),
                    not_valid_before=now,
                    not_valid_after=now,
                    certificate_builder=builder,
                ),
            )
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.MODEL_CREATED,
            target=credential,
            target_display=f'Traceability Credential: {credential.name}',
            actor=cast('models.Model', self.request.user),
            details={'action': 'created'},
        )
        messages.success(self.request, _('Traceability Credential created successfully.'))
        return redirect('management:traceability_credential_detail', pk=credential.pk)


class TraceabilityCredentialEditView(
    UserPermissionRequiredMixin,
    TraceabilityCredentialContextMixin,
    FormView[TraceabilityCredentialDescriptionForm],
):
    """Edit only the mutable description field."""

    form_class = TraceabilityCredentialDescriptionForm
    template_name = 'management/traceability_credential/form.html'
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Load the logical credential before form processing."""
        self.credential = get_object_or_404(TraceabilityCredentialModel, pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self) -> dict[str, str]:
        """Prefill the current description."""
        return {'description': self.credential.description}

    def form_valid(self, form: TraceabilityCredentialDescriptionForm) -> HttpResponse:
        """Delegate the metadata mutation to the service."""
        credential = TraceabilityCredentialService.update_description(
            self.credential, form.cleaned_data['description']
        )
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
    FormView[TraceabilityCertificateForm],
):
    """Rotate an active Traceability Credential."""

    form_class = TraceabilityCertificateForm
    template_name = 'management/traceability_credential/form.html'
    permission_required = AppPermissions.MANAGE_TRACEABILITY_CREDENTIALS

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Load the logical credential before displaying the confirmation."""
        self.credential = get_object_or_404(TraceabilityCredentialModel, pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass the logical credential name to the profile form."""
        kwargs = super().get_form_kwargs()
        kwargs['credential_name'] = self.credential.name
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Expose the rotation title and credential to the template."""
        context = super().get_context_data(**kwargs)
        context['form_title'] = _('Rotate Traceability Credential')
        context['credential'] = self.credential
        return context

    def form_valid(self, form: TraceabilityCertificateForm) -> HttpResponse:
        """Delegate rotation and report failures without exposing key details."""
        try:
            builder = form.get_certificate_builder()
            generation = TraceabilityCredentialService.rotate(
                traceability_credential=self.credential,
                certificate_data=TraceabilityCertificateData(
                    subject=x509.Name([]),
                    not_valid_before=datetime.datetime.now(datetime.UTC),
                    not_valid_after=datetime.datetime.now(datetime.UTC),
                    certificate_builder=builder,
                ),
            )
        except ValidationError as error:
            form.add_error(None, error)
            return self.form_invalid(form)
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.MODEL_UPDATED,
            target=self.credential,
            target_display=f'Traceability Credential: {self.credential.name}',
            actor=cast('models.Model', self.request.user),
            details={'action': 'rotated', 'generation': generation.generation_number},
        )
        messages.success(self.request, _('Traceability Credential rotated successfully.'))
        return redirect('management:traceability_credential_detail', pk=self.credential.pk)


class TraceabilityCredentialRetireView(TraceabilityCredentialRotateView):
    """Retire an Traceability Credential irreversibly."""

    def form_valid(self, form: TraceabilityCertificateForm) -> HttpResponse:
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
