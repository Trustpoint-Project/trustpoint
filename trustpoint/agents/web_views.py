# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Web UI views for Agent Profile Definitions (Profiles) and assigned profiles."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING, Any, ClassVar

from django import forms
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models.deletion import ProtectedError
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.generic import FormView, ListView, UpdateView

from agents.api_views import next_update_after_success
from agents.models import AgentAssignedProfile, AgentProfileDefinition, TrustpointAgent
from agents.security import AgentSecurityMixin
from management.models import AuditLog
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import DEVICES_PAGE_AGENTS_SUBCATEGORY, DEVICES_PAGE_CATEGORY, PageContextMixin
from trustpoint.views.base import BulkDeleteView, UserPermissionRequiredMixin
from users.permissions import AppPermissions

if TYPE_CHECKING:
    from django.db.models import QuerySet


class AgentProfileDefinitionTableView(
    AgentSecurityMixin, PageContextMixin, LoggerMixin, ListView[AgentProfileDefinition]
):
    """View to list all Agent Profile Definitions."""

    http_method_names = ('get',)
    model = AgentProfileDefinition
    template_name = 'agents/profiles/list.html'
    context_object_name = 'profiles'
    paginate_by = 25
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_queryset(self) -> QuerySet[AgentProfileDefinition]:
        """Return all workflow definitions ordered by name, without decrypting secrets."""
        return AgentProfileDefinition.objects.defer('secrets').order_by('name')


class AgentProfileDefinitionConfigView(
    UserPermissionRequiredMixin,
    AgentSecurityMixin,
    PageContextMixin,
    LoggerMixin,
    UpdateView[AgentProfileDefinition, Any],
):
    """View to display and edit an Agent Profile Definition."""

    http_method_names = ('get', 'post')
    permission_required = AppPermissions.MANAGE_DEVICES
    model = AgentProfileDefinition
    success_url = reverse_lazy('agents:profiles')
    template_name = 'agents/profiles/config.html'
    context_object_name = 'profile'
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY
    fields: ClassVar[list[str]] = [  # type: ignore[misc]
        'name',
        'profile',
        'secrets',
        'is_active',
    ]

    def get_object(self, _queryset: QuerySet[Any] | None = None) -> AgentProfileDefinition | None:  # type: ignore[override]
        """Retrieve the AgentProfileDefinition object based on the primary key in the URL."""
        pk = self.kwargs.get('pk')
        if pk == 0:
            return None
        return get_object_or_404(AgentProfileDefinition, pk=pk)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parsed profile and secret JSON to the editor context."""
        context = super().get_context_data(**kwargs)
        form = context['form']

        if not self.object or not self.object.pk:
            context['is_new'] = True

        profile_value = form['profile'].value()
        parsed_profile, profile_valid = self._parse_form_json(profile_value)
        context['json_valid'] = profile_valid
        if profile_valid and isinstance(parsed_profile, dict):
            context['profile_json'] = parsed_profile
            context['profile_json_text'] = json.dumps(parsed_profile, indent=2, ensure_ascii=False)
        elif profile_value in (None, '', 'null'):
            default_profile = self._default_profile()
            context['profile_json'] = default_profile
            context['profile_json_text'] = json.dumps(default_profile, indent=2, ensure_ascii=False)
            context['json_valid'] = True
        else:
            context['json_valid'] = False
            context['profile_json'] = str(profile_value)
            context['profile_json_text'] = str(profile_value)

        secrets_value = form['secrets'].value()
        parsed_secrets, secrets_valid = self._parse_form_json(secrets_value)
        if secrets_valid and isinstance(parsed_secrets, dict):
            context['secrets_json'] = json.dumps(parsed_secrets, indent=2, ensure_ascii=False)
        elif secrets_value in (None, '', 'null'):
            context['secrets_json'] = '{}'
        else:
            context['secrets_json'] = str(secrets_value)
        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        if self.object and self.object.pk:
            initial['name'] = self.object.name
            initial['profile'] = self.object.profile or self._default_profile()
            initial['secrets'] = self.object.secrets or {}
            initial['is_active'] = self.object.is_active
        else:
            initial['profile'] = self._default_profile()
            initial['secrets'] = {}
        return initial

    @staticmethod
    def _parse_form_json(value: Any) -> tuple[Any, bool]:
        """Parse a form JSON value once, or twice when it is JSON-encoded as a string."""
        if isinstance(value, (dict, list)):
            return value, True
        if value in (None, '', 'null'):
            return None, True
        if not isinstance(value, str):
            return None, False
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None, False
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
            except json.JSONDecodeError:
                return None, False
        return parsed, True

    @staticmethod
    def _default_profile() -> dict[str, Any]:
        """Return the default workflow profile."""
        return {
            'metadata': {
                'agent_type': '1-to-1',
                'version': '1.0',
                'description': 'Description of the workflow',
            },
            'device': {
                'vendor': 'Vendor Name',
                'device_family': 'Webserver',
                'firmware': '1.0',
            },
            'certificate_request': {
                'certificate_profile': 'tls_server',
                'url': '{{ endpoint }}',
                'path': '{{ path }}',
            },
            'steps': [
                {
                    'type': 'goto',
                    'url': 'https://device.example.com',
                },
                {
                    'type': 'fill',
                    'selector': '#username',
                    'value': 'admin',
                },
                {
                    'type': 'fill',
                    'selector': '#password',
                    'value': '{{ secret:wbm_password }}',
                },
                {
                    'type': 'click',
                    'selector': '#login-button',
                },
                {
                    'type': 'waitFor',
                    'selector': '.dashboard',
                    'timeout_ms': 5000,
                },
                {
                    'type': 'screenshot',
                },
            ],
        }

    def form_valid(self, form: Any) -> Any:
        """Process form submission and save the profile plus its encrypted secrets."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_DEVICES):
            raise PermissionDenied
        created = not form.instance.pk
        profile_data = form.cleaned_data.get('profile')
        parsed_profile = profile_data
        if isinstance(profile_data, str):
            try:
                parsed_profile = json.loads(profile_data)
            except json.JSONDecodeError as exc:
                form.add_error('profile', f'Invalid JSON: {exc}')
                return self.form_invalid(form)
        if not isinstance(parsed_profile, dict):
            form.add_error('profile', 'Profile must be a JSON object.')
            return self.form_invalid(form)

        secrets_data = form.cleaned_data.get('secrets') or {}
        if not form.instance.pk:
            form.instance = AgentProfileDefinition()
            form.instance.name = form.cleaned_data.get('name')
            form.instance.is_active = form.cleaned_data.get('is_active', True)
        form.instance.profile = parsed_profile
        form.instance.secrets = secrets_data

        with transaction.atomic():
            response = super().form_valid(form)
            AuditLog.create_entry(
                operation_type=(
                    AuditLog.OperationType.AGENT_PROFILE_CREATED
                    if created
                    else AuditLog.OperationType.AGENT_PROFILE_UPDATED
                ),
                target=self.object,
                target_display=f'Agent Profile Definition: {self.object.name}',
                actor=self.request.user if self.request.user.is_authenticated else None,
                details={'name': self.object.name, 'is_active': self.object.is_active},
            )
        return response


class AgentProfileDefinitionBulkDeleteConfirmView(AgentSecurityMixin, PageContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple workflow definitions."""

    model = AgentProfileDefinition
    success_url = reverse_lazy('agents:profiles')
    ignore_url = reverse_lazy('agents:profiles')
    template_name = 'agents/profiles/confirm_delete.html'
    context_object_name = 'profiles'
    queryset: QuerySet[AgentProfileDefinition]
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_queryset(self) -> QuerySet[AgentProfileDefinition]:
        """Keep encrypted secret values out of the confirmation/delete queryset."""
        return super().get_queryset().defer('secrets')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, 'No profiles selected for deletion.')
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete the selected profiles on valid form."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_DEVICES):
            raise PermissionDenied
        queryset = self.get_queryset()
        profiles = list(queryset)
        sketches = [copy.copy(profile) for profile in profiles]
        deleted_count = len(profiles)
        try:
            with transaction.atomic():
                response = super().form_valid(form)
                actor = self.request.user if self.request.user.is_authenticated else None
                for profile in sketches:
                    AuditLog.create_entry(
                        operation_type=AuditLog.OperationType.AGENT_PROFILE_DELETED,
                        target=profile,
                        target_display=f'Agent Profile Definition: {profile.name}',
                        actor=actor,
                    )
        except ProtectedError as exc:
            names = ', '.join(str(profile) for profile in exc.protected_objects)
            messages.error(
                self.request,
                f'These profiles are still assigned to an agent and cannot be deleted: {names}',
            )
            return HttpResponseRedirect(self.success_url)

        messages.success(
            self.request,
            f'Successfully deleted {deleted_count} workflow definition(s).',
        )

        return response


class AgentAssignedProfileForm(forms.ModelForm[AgentAssignedProfile]):
    """Form for creating or editing an AgentAssignedProfile."""

    class Meta:
        """Meta options."""

        model = AgentAssignedProfile
        fields: ClassVar = ('workflow_definition', 'renewal_threshold_days', 'subject', 'subject_alt_name')
        widgets: ClassVar = {
            'subject': forms.TextInput(
                attrs={
                    'placeholder': '/C=DE/ST=Berlin/L=Berlin/O=Example GmbH/OU=IT/CN=www.example.com',
                    'class': 'form-control',
                }
            ),
            'subject_alt_name': forms.TextInput(
                attrs={
                    'placeholder': 'DNS:www.example.com,DNS:example.com,IP:192.0.2.10',
                    'class': 'form-control',
                }
            ),
        }
        help_texts: ClassVar = {
            'subject': 'OpenSSL-style subject DN. Leave empty to use default.',
            'subject_alt_name': 'OpenSSL-style SAN extension. Leave empty for no SAN.',
        }

    def __init__(self, *args: Any, agent: TrustpointAgent | None = None, **kwargs: Any) -> None:
        """Restrict the workflow queryset to active, unassigned definitions."""
        from django.forms import ModelChoiceField  # noqa: PLC0415

        super().__init__(*args, **kwargs)
        field = self.fields['workflow_definition']
        if isinstance(field, ModelChoiceField):
            queryset = AgentProfileDefinition.objects.filter(is_active=True)
            if agent is not None:
                queryset = queryset.exclude(pk__in=agent.assigned_profiles.values('workflow_definition_id'))
            field.queryset = queryset.order_by('name')


class AgentAssignedProfileEditForm(forms.ModelForm[AgentAssignedProfile]):
    """Form for editing an AgentAssignedProfile (excludes workflow_definition)."""

    class Meta:
        """Meta options."""

        model = AgentAssignedProfile
        fields: ClassVar = ('renewal_threshold_days', 'subject', 'subject_alt_name', 'enabled')
        widgets: ClassVar = {
            'subject': forms.TextInput(
                attrs={
                    'placeholder': '/C=DE/ST=Berlin/L=Berlin/O=Example GmbH/OU=IT/CN=www.example.com',
                    'class': 'form-control',
                }
            ),
            'subject_alt_name': forms.TextInput(
                attrs={
                    'placeholder': 'DNS:www.example.com,DNS:example.com,IP:192.0.2.10',
                    'class': 'form-control',
                }
            ),
        }
        help_texts: ClassVar = {
            'subject': 'OpenSSL-style subject DN. Leave empty to use default.',
            'subject_alt_name': 'OpenSSL-style SAN extension. Leave empty for no SAN.',
        }


class AgentContextMixin:
    """Add the parent agent to assigned-profile template contexts."""

    kwargs: dict[str, Any]

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Resolve the agent named by the URL after building the view context."""
        context = super().get_context_data(**kwargs)  # type: ignore[misc]
        context['agent'] = get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])
        return context  # type: ignore[no-any-return]


class AgentAssignedProfileTableView(
    AgentContextMixin, AgentSecurityMixin, PageContextMixin, LoggerMixin, ListView[AgentAssignedProfile]
):
    """List all workflow profiles assigned to a specific 1-to-1 agent."""

    http_method_names: ClassVar[list[str]] = ['get']  # type: ignore[misc]
    template_name = 'agents/assigned_profiles/list.html'
    context_object_name = 'assigned_profiles'
    paginate_by = 25
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_queryset(self) -> QuerySet[AgentAssignedProfile]:
        """Return assigned profiles for the agent, newest first."""
        agent_id: int = self.kwargs['agent_id']
        return (
            AgentAssignedProfile.objects.filter(agent_id=agent_id)
            .select_related('agent', 'workflow_definition')
            .defer('workflow_definition__secrets')
            .order_by('workflow_definition__name')
        )


class AgentAssignedProfileCreateView(
    AgentSecurityMixin, PageContextMixin, LoggerMixin, FormView[AgentAssignedProfileForm]
):
    """Assign a new workflow profile to a 1-to-1 agent."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']  # type: ignore[misc]
    template_name = 'agents/assigned_profiles/create.html'
    form_class = AgentAssignedProfileForm
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def _get_agent(self) -> TrustpointAgent:
        """Return the agent identified by the URL kwarg, or 404."""
        return get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parent agent to the template context."""
        context = super().get_context_data(**kwargs)
        context['agent'] = self._get_agent()
        return context

    def get_success_url(self) -> str:
        """Redirect to the assigned-profiles list after saving."""
        return str(reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    def get_form_kwargs(self) -> dict[str, Any]:
        """Give the form the agent so assigned profiles can be excluded."""
        kwargs = super().get_form_kwargs()
        kwargs['agent'] = self._get_agent()
        return kwargs

    def form_valid(self, form: AgentAssignedProfileForm) -> HttpResponse:
        """Save the assignment and show a success message."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_DEVICES):
            raise PermissionDenied

        agent = self._get_agent()
        assignment: AgentAssignedProfile = form.save(commit=False)
        assignment.agent = agent
        assignment.next_certificate_update_scheduled = timezone.now()
        try:
            assignment.full_clean()
        except ValidationError as exc:
            self._add_form_errors(form, exc)
            return self.form_invalid(form)
        with transaction.atomic():
            assignment.save()
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.MODEL_CREATED,
                target=assignment,
                target_display=f'Agent Assignment: {agent.name} / {assignment.workflow_definition.name}',
                actor=self.request.user if self.request.user.is_authenticated else None,
                details={'agent': agent.agent_id, 'profile': assignment.workflow_definition.name},
            )
        messages.success(
            self.request,
            f"Profile '{assignment.workflow_definition.name}' assigned to agent '{agent.name}'.",
        )
        return HttpResponseRedirect(self.get_success_url())

    @staticmethod
    def _add_form_errors(form: forms.ModelForm[Any], exc: ValidationError) -> None:
        """Attach model validation errors to matching form fields."""
        if hasattr(exc, 'message_dict'):
            for field, errors in exc.message_dict.items():
                form.add_error(field if field in form.fields else None, errors)
        else:
            form.add_error(None, exc.messages)


class AgentAssignedProfileEditView(
    AgentContextMixin,
    AgentSecurityMixin,
    PageContextMixin,
    LoggerMixin,
    UpdateView[AgentAssignedProfile, AgentAssignedProfileEditForm],
):
    """Edit an existing AgentAssignedProfile (renewal_threshold_days, subject, subject_alt_name)."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']  # type: ignore[misc]
    template_name = 'agents/assigned_profiles/edit.html'
    form_class = AgentAssignedProfileEditForm
    model = AgentAssignedProfile
    context_object_name = 'assignment'
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_queryset(self) -> QuerySet[AgentAssignedProfile]:
        """Restrict to profiles belonging to the specified agent without decrypting secrets."""
        return (
            AgentAssignedProfile.objects.filter(agent_id=self.kwargs['agent_id'])
            .select_related('workflow_definition')
            .defer('workflow_definition__secrets')
        )

    def get_success_url(self) -> str:
        """Redirect to the assigned-profiles list after saving."""
        return str(reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    def form_valid(self, form: AgentAssignedProfileEditForm) -> HttpResponse:
        """Save the changes and show a success message."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_DEVICES):
            raise PermissionDenied
        assignment: AgentAssignedProfile = form.save(commit=False)
        if 'renewal_threshold_days' in form.changed_data:
            assignment.next_certificate_update_scheduled = next_update_after_success(
                assignment,
                timezone.now(),
            )
        with transaction.atomic():
            assignment.save()
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.MODEL_UPDATED,
                target=assignment,
                target_display=(f'Agent Assignment: {assignment.agent.name} / {assignment.workflow_definition.name}'),
                actor=self.request.user if self.request.user.is_authenticated else None,
                details={'changed_fields': list(form.changed_data)},
            )
        messages.success(
            self.request,
            f"Profile assignment '{assignment.workflow_definition.name}' updated successfully.",
        )
        return HttpResponseRedirect(self.get_success_url())


class AgentAssignedProfileDeleteView(AgentContextMixin, AgentSecurityMixin, PageContextMixin, BulkDeleteView):
    """Confirm and execute bulk deletion of AgentAssignedProfile records."""

    model = AgentAssignedProfile
    template_name = 'agents/assigned_profiles/confirm_delete.html'
    context_object_name = 'assigned_profiles'
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_queryset(self) -> QuerySet[AgentAssignedProfile]:
        """Restrict deletion to profiles belonging to the agent in the URL."""
        pks = self.get_pks_as_list(self.get_pks_path())
        if not pks:
            return AgentAssignedProfile.objects.none()
        return (
            AgentAssignedProfile.objects.filter(agent_id=self.kwargs['agent_id'], pk__in=pks)
            .select_related('agent', 'workflow_definition')
            .defer('workflow_definition__secrets')
        )

    def get_success_url(self) -> str:
        """Return to the assigned-profiles list after deletion."""
        return str(reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    @property
    def ignore_url(self) -> str:
        """Return the list URL to go back without deleting."""
        return str(reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Show confirmation page, or redirect back if nothing is selected."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, 'No profiles selected for deletion.')
            return HttpResponseRedirect(self.ignore_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete selected assignments and redirect."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_DEVICES):
            raise PermissionDenied
        queryset = self.get_queryset()
        assignments = [copy.copy(assignment) for assignment in queryset]
        deleted_count = len(assignments)
        with transaction.atomic():
            response = super().form_valid(form)
            actor = self.request.user if self.request.user.is_authenticated else None
            for assignment in assignments:
                AuditLog.create_entry(
                    operation_type=AuditLog.OperationType.MODEL_DELETED,
                    target=assignment,
                    target_display=(
                        f'Agent Assignment: {assignment.agent.name} / {assignment.workflow_definition.name}'
                    ),
                    actor=actor,
                )
        messages.success(self.request, f'Successfully removed {deleted_count} profile assignment(s).')
        return response


class AgentAssignedProfileForceUpdateView(AgentSecurityMixin, PageContextMixin, LoggerMixin, View):
    """Force an immediate certificate update by setting next_certificate_update_scheduled to now."""

    http_method_names: ClassVar[list[str]] = ['post']  # type: ignore[misc]
    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def post(self, request: HttpRequest, agent_id: int, pk: int) -> HttpResponse:
        """Set next_certificate_update_scheduled to now and redirect back to list."""
        if not self.request.user.has_perm(AppPermissions.MANAGE_DEVICES):
            raise PermissionDenied

        assignment = get_object_or_404(
            AgentAssignedProfile.objects.select_related('workflow_definition').defer('workflow_definition__secrets'),
            pk=pk,
            agent_id=agent_id,
        )

        assignment.next_certificate_update_scheduled = timezone.now()
        assignment.claimed_at = None
        assignment.claim_token = None
        with transaction.atomic():
            assignment.save(update_fields=['next_certificate_update_scheduled', 'claimed_at', 'claim_token'])
            AuditLog.create_entry(
                operation_type=AuditLog.OperationType.MODEL_UPDATED,
                target=assignment,
                target_display=(f'Agent Assignment: {assignment.agent.name} / {assignment.workflow_definition.name}'),
                actor=request.user if request.user.is_authenticated else None,
                details={'action': 'force_renewal'},
            )

        messages.success(
            request,
            f"Certificate update scheduled immediately for '{assignment.workflow_definition.name}'.",
        )

        return HttpResponseRedirect(reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': agent_id}))
