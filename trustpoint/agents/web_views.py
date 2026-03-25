"""Web UI views for Agent Workflow Definitions (Profiles) and managed device targets."""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING, Any, ClassVar

from django import forms
from django.contrib import messages
from django.db import transaction
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views.generic import FormView, ListView, UpdateView

from agents.models import AgentCertificateTarget, AgentWorkflowDefinition, TrustpointAgent
from trustpoint.logger import LoggerMixin
from trustpoint.views.base import BulkDeleteView

if TYPE_CHECKING:
    from django.db.models import QuerySet




# ---------------------------------------------------------------------------
# Managed device creation form
# ---------------------------------------------------------------------------

class ManagedDeviceCreateForm(forms.Form):
    """Form to create a new managed device and link it to an agent as a certificate target."""

    common_name = forms.CharField(
        max_length=100,
        label='Common Name',
        help_text='Unique name for the managed device.',
    )
    serial_number = forms.CharField(
        max_length=100,
        required=False,
        label='Serial Number',
    )
    ip_address = forms.GenericIPAddressField(
        protocol='both',
        unpack_ipv4=True,
        required=False,
        empty_value=None,
        label='IP Address',
        help_text='IP address of the managed device.',
    )
    certificate_profile = forms.ModelChoiceField(
        queryset=None,  # set in __init__
        empty_label='-- Select Certificate Profile --',
        label='Certificate Profile',
    )
    workflow = forms.ModelChoiceField(
        queryset=None,  # set in __init__
        empty_label='-- Select Workflow Definition --',
        required=True,
        label='Workflow Definition',
    )
    renewal_threshold_days = forms.IntegerField(
        min_value=0,
        initial=30,
        label='Renewal Threshold (days)',
        help_text='Days before expiry to trigger renewal.',
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise querysets at runtime."""
        super().__init__(*args, **kwargs)
        from pki.models import CertificateProfileModel  # noqa: PLC0415
        self.fields['certificate_profile'].queryset = CertificateProfileModel.objects.all().order_by('unique_name')  # type: ignore[union-attr]
        self.fields['workflow'].queryset = AgentWorkflowDefinition.objects.filter(is_active=True).order_by('name')  # type: ignore[union-attr]

    def clean_common_name(self) -> str:
        """Ensure the common name is unique across all devices."""
        from devices.models import DeviceModel  # noqa: PLC0415
        name: str = self.cleaned_data['common_name']
        if DeviceModel.objects.filter(common_name=name).exists():
            msg = 'A device with this common name already exists.'
            raise forms.ValidationError(msg)
        return name

    def clean_ip_address(self) -> str | None:
        """Return None for blank IP address instead of raising a validation error."""
        value: str = self.cleaned_data.get('ip_address') or ''
        return value.strip() or None

    @transaction.atomic
    def save(self, agent: TrustpointAgent) -> AgentCertificateTarget:
        """Create the DeviceModel + OnboardingConfig + AgentCertificateTarget atomically."""
        import secrets as _secrets  # noqa: PLC0415

        from devices.models import DeviceModel  # noqa: PLC0415
        from onboarding.enums import OnboardingPkiProtocol, OnboardingProtocol, OnboardingStatus  # noqa: PLC0415
        from onboarding.models import OnboardingConfigModel  # noqa: PLC0415

        # Agent-managed devices are onboarded via the agent using REST with a generated password.
        onboarding_config = OnboardingConfigModel(
            onboarding_status=OnboardingStatus.PENDING,
            onboarding_protocol=OnboardingProtocol.AGENT,
            est_password=_secrets.token_urlsafe(16),
        )
        onboarding_config.set_pki_protocols([OnboardingPkiProtocol.REST])
        onboarding_config.save()

        device = DeviceModel(
            common_name=self.cleaned_data['common_name'],
            serial_number=self.cleaned_data.get('serial_number') or '',
            ip_address=self.cleaned_data.get('ip_address') or None,
            device_type=DeviceModel.DeviceType.AGENT_MANAGED_DEVICE,
            domain=agent.device.domain if agent.device else None,
        )
        device.onboarding_config = onboarding_config
        device.save()

        target = AgentCertificateTarget(
            device=device,
            agent=agent,
            certificate_profile=self.cleaned_data['certificate_profile'],
            workflow=self.cleaned_data.get('workflow'),
            renewal_threshold_days=self.cleaned_data.get('renewal_threshold_days') or 30,
        )
        target.save()
        return target




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


# ---------------------------------------------------------------------------
# Agent managed device table view
# ---------------------------------------------------------------------------


class AgentManagedDeviceTableView(LoggerMixin, ListView[AgentCertificateTarget]):
    """List all devices managed by a specific agent (as AgentCertificateTargets)."""

    http_method_names: ClassVar[list[str]] = ['get']
    template_name = 'agents/targets/list.html'
    context_object_name = 'targets'
    paginate_by = 25

    def get_queryset(self) -> QuerySet[AgentCertificateTarget]:
        """Return certificate targets filtered by agent."""
        agent_id: int = self.kwargs['agent_id']
        return (
            AgentCertificateTarget.objects.filter(agent_id=agent_id)
            .select_related('device', 'agent', 'certificate_profile', 'workflow')
            .order_by('device__common_name')
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the agent object and a delete-confirmation URL to the template context."""
        context = super().get_context_data(**kwargs)
        agent_id: int = self.kwargs['agent_id']
        context['agent'] = get_object_or_404(TrustpointAgent, pk=agent_id)
        return context


# ---------------------------------------------------------------------------
# Agent managed device create view
# ---------------------------------------------------------------------------


class AgentManagedDeviceCreateView(LoggerMixin, FormView[ManagedDeviceCreateForm]):
    """Create a new managed device and its AgentCertificateTarget in one step."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    template_name = 'agents/targets/create.html'
    form_class = ManagedDeviceCreateForm

    def _get_agent(self) -> TrustpointAgent:
        """Return the agent identified by the URL kwarg, or 404."""
        return get_object_or_404(TrustpointAgent, pk=self.kwargs['agent_id'])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parent agent to the template context."""
        context = super().get_context_data(**kwargs)
        context['agent'] = self._get_agent()
        return context

    def get_success_url(self) -> str:
        """Redirect to the managed-devices list for this agent after saving."""
        return str(reverse_lazy('agents:targets-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    def form_valid(self, form: ManagedDeviceCreateForm) -> HttpResponse:
        """Save the form, show a success message, then redirect."""
        agent = self._get_agent()
        target = form.save(agent)
        messages.success(
            self.request,
            f"Device '{target.device.common_name}' added and linked to agent '{agent}'.",
        )
        return HttpResponseRedirect(self.get_success_url())


# ---------------------------------------------------------------------------
# Agent managed device bulk-delete view
# ---------------------------------------------------------------------------


class AgentManagedDeviceDeleteView(BulkDeleteView):
    """Confirm and execute bulk deletion of AgentCertificateTarget records."""

    model = AgentCertificateTarget
    template_name = 'agents/targets/confirm_delete.html'
    context_object_name = 'targets'

    def get_success_url(self) -> str:
        """Return to the managed-devices list for this agent after deletion."""
        return str(reverse_lazy('agents:targets-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    @property
    def ignore_url(self) -> str:  # type: ignore[override]
        """Return the list URL to go back without deleting."""
        return str(reverse_lazy('agents:targets-list', kwargs={'agent_id': self.kwargs['agent_id']}))

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Show confirmation page, or redirect back if nothing is selected."""
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
        """Delete the selected targets and redirect."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0
        response = super().form_valid(form)
        messages.success(self.request, f'Successfully deleted {deleted_count} device(s).')
        return response
