"""Table View listing devices that are registered as automation agents (1-to-1 or 1-to-n)."""

from typing import Any

from django.db.models import QuerySet
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView

from devices.forms import (
    AgentOnboardingCreateForm,
)

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from devices.views.tables import AbstractDeviceTableView
from trustpoint.page_context import (
    DEVICES_PAGE_AGENTS_SUBCATEGORY,
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    PageContextMixin,
)


class AgentTableView(AbstractDeviceTableView):
    """Table View listing devices that are registered as automation agents (1-to-1 or 1-to-n)."""

    template_name = 'devices/agents.html'

    # Use the existing 'devices' page_name so that the base-class reverse() calls for
    # device_revoke_url and device_delete_url resolve to valid URL patterns.
    # Agent devices share the same bulk-action endpoints as generic devices.
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to only include agent device types, filtered by UI filters.

        Returns:
            Returns a queryset of DeviceModels with type AGENT_ONE_TO_ONE or AGENT_ONE_TO_N.
        """
        _agent_types = [DeviceModel.DeviceType.AGENT_ONE_TO_ONE, DeviceModel.DeviceType.AGENT_ONE_TO_N]
        base_qs = super(ListView, self).get_queryset().filter(device_type__in=_agent_types)
        return self.apply_filters(base_qs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Extends base context with agent-specific data (linked agents per device).

        The base class resolves URL names using ``self.page_name``; by keeping
        ``page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY`` those reverse() calls always
        succeed.  We then fix ``page_name`` in the context so the template highlights
        the correct sidebar entry.

        Args:
            **kwargs: Passed to super().get_context_data().

        Returns:
            Context dict; each device in ``page_obj`` gains an ``agent_list`` attribute.
        """
        from agents.models import TrustpointAgent  # noqa: PLC0415

        context = super().get_context_data(**kwargs)

        # Correct the page_name so the 'Agents' sidebar item is highlighted.
        context['page_name'] = DEVICES_PAGE_AGENTS_SUBCATEGORY

        device_pks = [d.pk for d in context['devices']]

        # Auto-create a TrustpointAgent for any agent device that doesn't have one yet,
        # so the "Managed Devices" button is always available.
        existing_device_ids = set(
            TrustpointAgent.objects.filter(device_id__in=device_pks).values_list('device_id', flat=True)
        )
        for device in context['devices']:
            if device.pk not in existing_device_ids:
                TrustpointAgent.objects.create(
                    name=device.common_name,
                    device=device,
                )

        agents_qs = (
            TrustpointAgent.objects.filter(device_id__in=device_pks)
            .select_related('device')
            .order_by('device_id', 'name')
        )
        agents_by_device: dict[int, list[TrustpointAgent]] = {}
        for agent in agents_qs:
            agents_by_device.setdefault(agent.device_id, []).append(agent)
        # Attach directly to device objects so the template needs no custom filter.
        for device in context['devices']:
            device.agent_list = agents_by_device.get(device.pk, [])

        # Point "Create Agent Device" at the dedicated agent type-selection page.
        context['create_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_create'
        return context


# ------------------------------------------------ Agent Create Views -------------------------------------------------


class AgentCreateChooseTypeView(PageContextMixin, TemplateView):
    """Landing page for agent device creation — lets the operator choose 1-to-1 or 1-to-n."""

    http_method_names = ('get',)
    template_name = 'devices/agent_create_choose_type.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add cancel and creation target URLs to context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            Context dict with agent-type creation URLs.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}'
        context['create_one_to_n_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}_create_one_to_n'
        return context


class AgentCreateOneToNOnboardingView(PageContextMixin, FormView[AgentOnboardingCreateForm]):
    """Create a new 1-to-n (WBM) agent device using the standard onboarding form."""

    http_method_names = ('get', 'post')
    form_class = AgentOnboardingCreateForm
    template_name = 'devices/create.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_AGENTS_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add cancel URL to context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            Context dict with cancel URL.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_AGENTS_SUBCATEGORY}'
        return context

    def form_valid(self, form: AgentOnboardingCreateForm) -> HttpResponse:
        """Save the form as an AGENT_ONE_TO_N device.

        Args:
            form: The valid form.

        Returns:
            Redirect to the CLM page for the created device.
        """
        self.object = form.save(device_type=DeviceModel.DeviceType.AGENT_ONE_TO_N)
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
