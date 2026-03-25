"""Table View listing devices that are registered as automation agents (1-to-1 or 1-to-n)."""

import secrets
import uuid
from typing import Any

from django.db.models import QuerySet
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView

from agents.models import (
    AgentAssignedProfile,
    AgentWorkflowDefinition,
    TrustpointAgent,
)
from devices.forms import (
    AgentOnboardingCreateForm,
)
from devices.models import (
    DeviceModel,
)
from devices.views.tables import AbstractDeviceTableView
from onboarding.enums import NoOnboardingPkiProtocol
from onboarding.models import NoOnboardingConfigModel
from trustpoint.page_context import (
    DEVICES_PAGE_AGENTS_SUBCATEGORY,
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    PageContextMixin,
)


class AgentTableView(AbstractDeviceTableView):
    """Table View listing devices that are registered as automation agents (1-to-1 or 1-to-n)."""

    template_name = 'devices/agents.html'

    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to only include agent device types, filtered by UI filters."""
        _agent_types = [DeviceModel.DeviceType.AGENT_ONE_TO_ONE, DeviceModel.DeviceType.AGENT_ONE_TO_N]
        base_qs = super(ListView, self).get_queryset().filter(device_type__in=_agent_types)
        return self.apply_filters(base_qs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Extends base context with agent-specific data (linked agents per device)."""
        from agents.models import TrustpointAgent  # noqa: PLC0415

        context = super().get_context_data(**kwargs)

        context['page_name'] = DEVICES_PAGE_AGENTS_SUBCATEGORY

        device_pks = [d.pk for d in context['devices']]

        agents_qs = (
            TrustpointAgent.objects.filter(device_id__in=device_pks)
            .select_related('device')
            .order_by('device_id', 'name')
        )
        agents_by_device: dict[int, list[TrustpointAgent]] = {}
        for agent in agents_qs:
            agents_by_device.setdefault(agent.device_id, []).append(agent)
        for device in context['devices']:
            device.agent_list = agents_by_device.get(device.pk, [])

        context['create_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_create'
        return context


class AgentCreateChooseTypeView(PageContextMixin, TemplateView):
    """Landing page for agent device creation — lets the operator choose 1-to-1 or 1-to-n."""

    http_method_names = ('get',)
    template_name = 'devices/agent_create_choose_type.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add cancel and creation target URLs to context."""
        context = super().get_context_data(**kwargs)
        context['cancel_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}'
        context['create_one_to_n_url'] = (
            f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_create_one_to_n'
        )
        context['create_one_to_one_url'] = (
            f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_create_one_to_one'
        )
        return context


class AgentCreateOneToNOnboardingView(PageContextMixin, FormView[AgentOnboardingCreateForm]):
    """Create a new 1-to-n (WBM) agent device using the standard onboarding form."""

    http_method_names = ('get', 'post')
    form_class = AgentOnboardingCreateForm
    template_name = 'devices/create.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add cancel URL to context."""
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}'
        return context

    def form_valid(self, form: AgentOnboardingCreateForm) -> HttpResponse:
        """Save the form as an AGENT_ONE_TO_N device."""
        self.object = form.save(device_type=DeviceModel.DeviceType.AGENT_ONE_TO_N)
        agent_uuid = uuid.uuid4().hex.upper()
        TrustpointAgent.objects.create(
            name=self.object.common_name,
            agent_id=agent_uuid,
            certificate_fingerprint=agent_uuid,
            device=self.object,
        )

        _allowed_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        no_onboarding_config = NoOnboardingConfigModel()
        no_onboarding_config.add_pki_protocol(NoOnboardingPkiProtocol.REST_USERNAME_PASSWORD)
        no_onboarding_config.est_password = ''.join(secrets.choice(_allowed_chars) for _ in range(16))
        no_onboarding_config.full_clean()
        no_onboarding_config.save()

        managed_device = DeviceModel(
            common_name=f'{self.object.common_name} (self)',
            serial_number=self.object.serial_number,
            ip_address=self.object.ip_address,
            domain=self.object.domain,
            device_type=DeviceModel.DeviceType.AGENT_MANAGED_DEVICE,
            no_onboarding_config=no_onboarding_config,
        )
        managed_device.full_clean()
        managed_device.save()

        managed_device_uuid = uuid.uuid4().hex.upper()
        managed_agent = TrustpointAgent.objects.create(
            name=f'{self.object.common_name} (self)',
            agent_id=managed_device_uuid,
            certificate_fingerprint=managed_device_uuid,
            device=managed_device,
        )

        default_wf = AgentWorkflowDefinition.objects.filter(
            name='Domain Credential Update', is_active=True
        ).first()
        if default_wf is not None:
            AgentAssignedProfile.objects.get_or_create(
                agent=managed_agent,
                workflow_definition=default_wf,
                defaults={
                    'renewal_threshold_days': 30,
                    'next_certificate_update_scheduled': timezone.now(),
                },
            )

        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Return the CLM URL for the newly created agent device.

        Returns:
            URL string for the device's certificate lifecycle management page.
        """
        return str(
            reverse_lazy(
                f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management',
                kwargs={'pk': self.object.id},
            )
        )


class AgentCreateOneToOneOnboardingView(PageContextMixin, FormView[AgentOnboardingCreateForm]):
    """Create a new 1-to-1 agent device using the standard onboarding form."""

    http_method_names = ('get', 'post')
    form_class = AgentOnboardingCreateForm
    template_name = 'devices/create.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add cancel URL and 1-to-1 flag to context."""
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}'
        context['is_one_to_one_agent'] = True
        return context

    def form_valid(self, form: AgentOnboardingCreateForm) -> HttpResponse:
        """Save the form as an AGENT_ONE_TO_ONE device."""
        self.object = form.save(device_type=DeviceModel.DeviceType.AGENT_ONE_TO_ONE)
        agent_uuid = uuid.uuid4().hex.upper()
        agent = TrustpointAgent.objects.create(
            name=self.object.common_name,
            agent_id=agent_uuid,
            certificate_fingerprint=agent_uuid,
            device=self.object,
        )

        default_wf = AgentWorkflowDefinition.objects.filter(
            name='Domain Credential Update', is_active=True
        ).first()
        if default_wf is not None:
            AgentAssignedProfile.objects.get_or_create(
                agent=agent,
                workflow_definition=default_wf,
                defaults={
                    'renewal_threshold_days': 30,
                    'next_certificate_update_scheduled': timezone.now(),
                },
            )

        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Return the CLM URL for the newly created 1-to-1 agent device."""
        return str(
            reverse_lazy(
                f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_certificate_lifecycle_management',
                kwargs={'pk': self.object.id},
            )
        )
