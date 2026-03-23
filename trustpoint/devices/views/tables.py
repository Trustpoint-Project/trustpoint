"""Views for rendering device and certificate table listings."""

import abc
from collections.abc import Sequence
from typing import Any, cast

from django.db.models import QuerySet
from django.http import HttpResponse, HttpResponseRedirect
from django.http.request import HttpRequest
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy
from django.views.generic.list import ListView

from devices.filters import DeviceFilter

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)
from trustpoint.settings import UIConfig

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

class AbstractDeviceTableView(PageContextMixin, ListView[DeviceModel], abc.ABC):
    """Device Table View."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'devices'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'common_name'
    filterset_class = DeviceFilter

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def apply_filters(self, qs: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
        """Applies the `DeviceFilter` to the given queryset.

        Args:
            qs: The base queryset to filter.

        Returns:
            The filtered queryset according to GET parameters.
        """
        self.filterset = DeviceFilter(self.request.GET, queryset=qs)
        return cast('QuerySet[DeviceModel]', self.filterset.qs)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Adds the object model to the instance and forwards to super().get().

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            The HttpResponse object returned by super().get().
        """
        sort_params = request.GET.getlist('sort', [self.default_sort_param])

        if len(sort_params) > 1:
            first_sort_parameter = sort_params[0]

            query_dict = request.GET.copy()
            query_dict.setlist('sort', [first_sort_parameter])

            new_url = f'{request.path}?{query_dict.urlencode()}'
            return HttpResponseRedirect(new_url)

        self.ordering = sort_params[0]

        return super().get(request, *args, **kwargs)

    @abc.abstractmethod
    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to only include devices which are of generic type.

        Returns:
            Returns a queryset of all DeviceModels which are of generic type.
        """
        ...

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the clm and revoke buttons to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        context['current_sort'] = sort_param
        context['filter'] = getattr(self, 'filterset', None)

        params = self.request.GET.copy()
        params.pop('sort', None)
        context['preserve_qs'] = params.urlencode()

        for device in context['devices']:
            device.clm_button = self._get_clm_button_html(device)
            device.pki_protocols = self._get_pki_protocols(device)
        context['create_url'] = f'{self.page_category}:{self.page_name}_create'
        context['new_onboarding_url'] = f'{self.page_category}:{self.page_name}_new_onboarding'
        context['device_revoke_url'] = reverse(f'{self.page_category}:{self.page_name}_device_revoke')
        context['device_delete_url'] = reverse(f'{self.page_category}:{self.page_name}_device_delete')

        return context

    def get_ordering(self) -> str | Sequence[str] | None:
        """Returns the sort parameters as a list.

        Returns:
           The sort parameters, if any. Otherwise the default sort parameter.
        """
        return self.request.GET.getlist('sort', [self.default_sort_param])

    def _get_clm_button_html(self, record: DeviceModel) -> SafeString:
        """Gets the HTML for the CLM button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            The HTML of the hyperlink for the CLM button.
        """
        if record.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH:
            clm_url = reverse('devices:opc_ua_gds_push_certificate_lifecycle_management', kwargs={'pk': record.pk})
        else:
            clm_url = reverse(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': record.pk}
            )

        return format_html(
            '<a href="{}" class="btn btn-primary tp-table-btn w-100">{}</a>', clm_url, gettext_lazy('Manage')
        )

    def _get_pki_protocols(self, record: DeviceModel) -> str:
        if record.onboarding_config:
            return ', '.join([str(p.label) for p in record.onboarding_config.get_pki_protocols()])

        if record.no_onboarding_config:
            return ', '.join([str(p.label) for p in record.no_onboarding_config.get_pki_protocols()])

        return ''


class DeviceTableView(AbstractDeviceTableView):
    """Device Table View."""

    template_name = 'devices/devices.html'

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to include all device types (Generic, OPC UA GDS Push) and filtered by UI filters.

        Returns:
            Returns a queryset of all DeviceModels (excluding OPC UA GDS), filtered by UI filters.
        """
        base_qs = super(ListView, self).get_queryset().exclude(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS
        )
        return self.apply_filters(base_qs)


class OpcUaGdsTableView(DeviceTableView):
    """Table View for devices where opc_ua_gds is True."""

    template_name = 'devices/opc_ua_gds.html'

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to only include devices which are of OPC-UA GDS type and filtered by UI filters.

        Returns:
            Returns a queryset of all DeviceModels which are of OPC-UA GDS type, filtered by UI filters.
        """
        base_qs = super(ListView, self).get_queryset().filter(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS
        )
        return self.apply_filters(base_qs)
