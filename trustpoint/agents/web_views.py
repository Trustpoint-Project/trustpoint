"""Web UI views for Agent Workflow Definitions (Profiles) and assigned profiles."""

from __future__ import annotations

import contextlib
import json
import secrets
from typing import TYPE_CHECKING, Any, ClassVar

from django import forms
from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import FormView, ListView, UpdateView

from agents.models import AgentAssignedProfile, AgentWorkflowDefinition, TrustpointAgent
from trustpoint.logger import LoggerMixin
from trustpoint.views.base import BulkDeleteView

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from devices.models import DeviceModel


class AgentWorkflowDefinitionTableView(LoggerMixin, ListView[AgentWorkflowDefinition]):
    """View to list all Agent Workflow Definitions."""

    http_method_names = ('get',)
    model = AgentWorkflowDefinition
    template_name = 'agents/profiles/list.html'
    context_object_name = 'profiles'
    paginate_by = 25

    def get_queryset(self) -> QuerySet[AgentWorkflowDefinition]:
        """Return all workflow definitions ordered by name."""
        return AgentWorkflowDefinition.objects.all().order_by('name')


class AgentWorkflowDefinitionConfigView(LoggerMixin, UpdateView[AgentWorkflowDefinition, Any]):
    """View to display and edit an Agent Workflow Definition."""

    http_method_names = ('get', 'post')
    model = AgentWorkflowDefinition
    success_url = reverse_lazy('agents:profiles')
    template_name = 'agents/profiles/config.html'
    context_object_name = 'profile'
    fields: ClassVar[list[str]] = [
        'name',
        'profile',
        'is_active',
    ]

    def get_object(self, _queryset: QuerySet[Any] | None = None) -> AgentWorkflowDefinition | None:
        """Retrieve the AgentWorkflowDefinition object based on the primary key in the URL."""
        pk = self.kwargs.get('pk')
        if pk:
            return get_object_or_404(AgentWorkflowDefinition, pk=pk)
        return None

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data for JSON editor."""
        context = super().get_context_data(**kwargs)
        form = context['form']

        raw_json = form['profile'].value() or None

        if not self.object or not self.object.pk:
            context['is_new'] = True

        context['json_valid'] = True

        if not raw_json or raw_json == 'null':
            context['profile_json'] = self._default_profile_json()
            return context

        # Handle different JSON formats
        cleaned_raw = (
            raw_json.encode('utf-8').decode('unicode_escape')
            if isinstance(raw_json, str)
            else str(raw_json)
        )
        if cleaned_raw.startswith('"') and cleaned_raw.endswith('"'):
            cleaned_raw = cleaned_raw[1:-1]

        with contextlib.suppress(json.JSONDecodeError):
            context['profile_json'] = json.loads(cleaned_raw)
            return context

        with contextlib.suppress(json.JSONDecodeError):
            context['profile_json'] = (
                json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            )
            return context

        # Invalid JSON typed by the user - render as-is to revise
        context['json_valid'] = False
        context['profile_json'] = cleaned_raw
        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        if self.object and self.object.pk:
            initial['name'] = self.object.name
            if self.object.profile:
                initial['profile'] = json.dumps(self.object.profile)
            else:
                initial['profile'] = self._default_profile_json()
            initial['is_active'] = self.object.is_active
        else:
            # For new objects, provide a default profile with example steps
            initial['profile'] = self._default_profile_json()
        return initial

    @staticmethod
    def _default_profile_json() -> str:
        """Return a default workflow profile as JSON string."""
        default_profile = {
            'vendor': 'Vendor Name',
            'device_family': 'Device Family',
            'firmware_hint': '1.0',
            'version': '1.0',
            'description': 'Description of the workflow',
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
                    'value': 'password',
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
        return json.dumps(default_profile, indent=2)

    def form_valid(self, form: Any) -> Any:
        """Process form submission and parse profile JSON."""
        # Convert profile JSON string to dict
        profile_data = form.cleaned_data.get('profile')
        if isinstance(profile_data, str):
            try:
                parsed = json.loads(profile_data)
                # Ensure profile is a dict with 'steps' array
                if not isinstance(parsed, dict):
                    form.add_error('profile', 'Profile must be a JSON object.')
                    return self.form_invalid(form)
                form.instance.profile = parsed
            except json.JSONDecodeError as exc:
                form.add_error('profile', f'Invalid JSON: {exc}')
                return self.form_invalid(form)
        return super().form_valid(form)


class AgentWorkflowDefinitionBulkDeleteConfirmView(BulkDeleteView):
    """View to confirm the deletion of multiple workflow definitions."""

    model = AgentWorkflowDefinition
    success_url = reverse_lazy('agents:profiles')
    ignore_url = reverse_lazy('agents:profiles')
    template_name = 'agents/profiles/confirm_delete.html'
    context_object_name = 'profiles'
    queryset: QuerySet[AgentWorkflowDefinition]

    def get(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, 'No profiles selected for deletion.')
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete the selected profiles on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        response = super().form_valid(form)

        messages.success(
            self.request,
            f'Successfully deleted {deleted_count} workflow definition(s).',
        )

        return response


class AgentManagedDeviceTableView(LoggerMixin, ListView['DeviceModel']):
    """List all AGENT_MANAGED_DEVICE devices in the same domain as a 1-to-n agent's device."""

    http_method_names: ClassVar[list[str]] = ['get']
    template_name = 'agents/targets/list.html'
    context_object_name = 'devices'
    paginate_by = 25

    def _get_agent(self) -> TrustpointAgent:
        """Return the 1-to-n agent identified by the URL kwarg, or 404."""
        return get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Return all AGENT_MANAGED_DEVICE devices in the agent's domain."""
        from devices.models import DeviceModel  # noqa: PLC0415

        agent = self._get_agent()
        if agent.device is None or agent.device.domain is None:
            return DeviceModel.objects.none()
        return (
            DeviceModel.objects.filter(
                domain=agent.device.domain,
                device_type=DeviceModel.DeviceType.AGENT_MANAGED_DEVICE,
            )
            .select_related('domain')
            .prefetch_related('agents')
            .order_by('common_name')
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the agent to the template context."""
        context = super().get_context_data(**kwargs)
        context['agent'] = self._get_agent()
        return context


class ManagedDeviceCreateForm(forms.Form):
    """Form for creating a new AGENT_MANAGED_DEVICE under a 1-to-n agent."""

    common_name = forms.CharField(
        max_length=100,
        label='Common Name',
        help_text='Unique name for this managed device.',
    )
    serial_number = forms.CharField(
        max_length=100,
        required=False,
        label='Serial Number',
    )
    ip_address = forms.GenericIPAddressField(
        required=False,
        label='IP Address',
        help_text='IPv4 or IPv6 address of the managed device.',
    )


class AgentManagedDeviceCreateView(LoggerMixin, FormView[ManagedDeviceCreateForm]):
    """Create a new AGENT_MANAGED_DEVICE record under a 1-to-n agent."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    template_name = 'agents/targets/create.html'
    form_class = ManagedDeviceCreateForm

    def _get_agent(self) -> TrustpointAgent:
        """Return the 1-to-n agent, or 404."""
        return get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parent agent to context."""
        context = super().get_context_data(**kwargs)
        context['agent'] = self._get_agent()
        return context

    def get_success_url(self) -> str:
        """Redirect to the managed-devices list after creation."""
        return str(reverse_lazy('agents:targets-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    def form_valid(self, form: ManagedDeviceCreateForm) -> HttpResponse:
        """Create the DeviceModel record, its NoOnboardingConfigModel, and a TrustpointAgent."""
        import uuid  # noqa: PLC0415

        from devices.models import DeviceModel  # noqa: PLC0415
        from onboarding.enums import NoOnboardingPkiProtocol  # noqa: PLC0415
        from onboarding.models import NoOnboardingConfigModel  # noqa: PLC0415

        agent = self._get_agent()

        # Build a NoOnboardingConfigModel with REST enabled (same as other agent devices).
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD)
        no_onboarding_config.est_password = ''.join(
            secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
            for _ in range(16)
        )
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        device = DeviceModel(
            common_name=form.cleaned_data['common_name'],
            serial_number=form.cleaned_data.get('serial_number') or '',
            ip_address=form.cleaned_data.get('ip_address') or None,
            domain=agent.device.domain if agent.device else None,
            device_type=DeviceModel.DeviceType.AGENT_MANAGED_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )
        try:
            device.full_clean()
            device.save()
        except Exception as exc:  # noqa: BLE001
            no_onboarding_config.delete()
            messages.error(self.request, f'Could not create device: {exc}')
            return self.form_invalid(form)

        # Create a TrustpointAgent for this managed device so that AgentAssignedProfiles
        # can be assigned to it, exactly like a 1-to-1 agent.
        device_uuid = uuid.uuid4().hex.upper()
        TrustpointAgent.objects.create(
            name=device.common_name,
            agent_id=device_uuid,
            certificate_fingerprint=device_uuid,
            device=device,
        )

        messages.success(self.request, f"Managed device '{device.common_name}' created.")
        return HttpResponseRedirect(self.get_success_url())


class AgentManagedDeviceDeleteView(BulkDeleteView):
    """Confirm and bulk-delete AGENT_MANAGED_DEVICE records."""

    template_name = 'agents/targets/confirm_delete.html'
    context_object_name = 'devices'

    @property
    def model(self) -> type[DeviceModel]:  # type: ignore[override]
        """Return DeviceModel, imported lazily to avoid circular imports."""
        from devices.models import DeviceModel  # noqa: PLC0415

        return DeviceModel

    def get_success_url(self) -> str:
        """Redirect back to the managed-devices list."""
        return str(reverse_lazy('agents:targets-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    @property
    def ignore_url(self) -> str:  # type: ignore[override]
        """Return the list URL to go back without deleting."""
        return str(reverse_lazy('agents:targets-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Show confirmation page, or redirect back if nothing selected."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, 'No devices selected for deletion.')
            return HttpResponseRedirect(self.ignore_url)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parent agent to context."""
        context = super().get_context_data(**kwargs)
        context['agent'] = get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])
        return context

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete selected devices and redirect."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0
        response = super().form_valid(form)
        messages.success(self.request, f'Successfully deleted {deleted_count} managed device(s).')
        return response


class AgentAssignedProfileForm(forms.ModelForm[AgentAssignedProfile]):
    """Form for creating or editing an AgentAssignedProfile."""

    class Meta:
        """Meta options."""

        model = AgentAssignedProfile
        fields = ('workflow_definition', 'renewal_threshold_days')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Restrict the workflow queryset to active definitions."""
        super().__init__(*args, **kwargs)
        self.fields['workflow_definition'].queryset = (  # type: ignore[union-attr]
            AgentWorkflowDefinition.objects.filter(is_active=True).order_by('name')
        )


class AgentAssignedProfileTableView(LoggerMixin, ListView[AgentAssignedProfile]):
    """List all workflow profiles assigned to a specific 1-to-1 agent."""

    http_method_names: ClassVar[list[str]] = ['get']
    template_name = 'agents/assigned_profiles/list.html'
    context_object_name = 'assigned_profiles'
    paginate_by = 25

    def get_queryset(self) -> QuerySet[AgentAssignedProfile]:
        """Return assigned profiles for the agent, newest first."""
        agent_id: int = self.kwargs['agent_id']
        return (
            AgentAssignedProfile.objects.filter(agent_id=agent_id)
            .select_related('agent', 'workflow_definition')
            .order_by('workflow_definition__name')
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the agent to the template context."""
        context = super().get_context_data(**kwargs)
        context['agent'] = get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])
        return context


class AgentAssignedProfileCreateView(LoggerMixin, FormView[AgentAssignedProfileForm]):
    """Assign a new workflow profile to a 1-to-1 agent."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    template_name = 'agents/assigned_profiles/create.html'
    form_class = AgentAssignedProfileForm

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
        return str(
            reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': self.kwargs['agent_id']})
        )

    def form_valid(self, form: AgentAssignedProfileForm) -> HttpResponse:
        """Save the assignment and show a success message."""
        from django.utils import timezone  # noqa: PLC0415

        agent = self._get_agent()
        assignment: AgentAssignedProfile = form.save(commit=False)
        assignment.agent = agent
        assignment.next_certificate_update_scheduled = timezone.now()
        assignment.full_clean()
        assignment.save()
        messages.success(
            self.request,
            f"Profile '{assignment.workflow_definition.name}' assigned to agent '{agent.name}'.",
        )
        return HttpResponseRedirect(self.get_success_url())


class AgentAssignedProfileDeleteView(BulkDeleteView):
    """Confirm and execute bulk deletion of AgentAssignedProfile records."""

    model = AgentAssignedProfile
    template_name = 'agents/assigned_profiles/confirm_delete.html'
    context_object_name = 'assigned_profiles'

    def get_success_url(self) -> str:
        """Return to the assigned-profiles list after deletion."""
        return str(
            reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': self.kwargs['agent_id']})
        )

    @property
    def ignore_url(self) -> str:  # type: ignore[override]
        """Return the list URL to go back without deleting."""
        return str(
            reverse_lazy('agents:assigned-profiles-list', kwargs={'agent_id': self.kwargs['agent_id']})
        )

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Show confirmation page, or redirect back if nothing is selected."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, 'No profiles selected for deletion.')
            return HttpResponseRedirect(self.ignore_url)
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parent agent to context."""
        context = super().get_context_data(**kwargs)
        context['agent'] = get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])
        return context

    def form_valid(self, form: Any) -> HttpResponse:
        """Delete selected assignments and redirect."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0
        response = super().form_valid(form)
        messages.success(self.request, f'Successfully removed {deleted_count} profile assignment(s).')
        return response
