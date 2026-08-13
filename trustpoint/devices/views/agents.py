# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Table View listing devices that are registered as automation agents (1-to-1)."""

import uuid
from datetime import timedelta
from typing import Any

from django.db.models import QuerySet
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic.edit import FormView

from agents.models import (
    AgentAssignedProfile,
    AgentProfileDefinition,
    TrustpointAgent,
)
from devices.forms import (
    AgentOnboardingCreateForm,
)
from devices.models import (
    DeviceModel,
)
from devices.views.tables import AbstractDeviceTableView
from trustpoint.page_context import (
    DEVICES_PAGE_AGENTS_SUBCATEGORY,
    DEVICES_PAGE_CATEGORY,
    PageContextMixin,
)


class AgentTableView(AbstractDeviceTableView):
    """Table View listing devices that are registered as automation agents (1-to-1)."""

    template_name = 'devices/agents.html'

    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    @property
    def device_revoke_url_name(self) -> str:
        """Returns the URL name for the device revoke action, using the agents subcategory."""
        return f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_device_revoke'

    @property
    def device_delete_url_name(self) -> str:
        """Returns the URL name for the device delete action, using the agents subcategory."""
        return f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_device_delete'

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to only include agent device types, filtered by UI filters."""
        _agent_types = [DeviceModel.DeviceType.AGENT_ONE_TO_ONE]
        base_qs = self.get_base_queryset().filter(device_type__in=_agent_types)
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
            if agent.device_id is not None:
                agents_by_device.setdefault(agent.device_id, []).append(agent)
        for device in context['devices']:
            device.agent_list = agents_by_device.get(device.pk, [])

        context['create_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_create_one_to_one'
        return context


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
        agent_os_path = form.cleaned_data.get('agent_os_path', '/etc/trustpoint')
        agent = TrustpointAgent.objects.create(
            name=self.object.common_name,
            agent_id=agent_uuid,
            device=self.object,
            os_path=agent_os_path,
        )

        default_wf = AgentProfileDefinition.objects.filter(
            name='Domain Credential Update', is_active=True
        ).first()
        if default_wf is not None:
            AgentAssignedProfile.objects.get_or_create(
                agent=agent,
                workflow_definition=default_wf,
                defaults={
                    'renewal_threshold_days': 30,
                    'next_certificate_update_scheduled': timezone.now() + timedelta(days=30),
                },
            )

        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Return the agents list URL after successfully creating a 1-to-1 agent device."""
        return str(reverse_lazy(f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}'))
