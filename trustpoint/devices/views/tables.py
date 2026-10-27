# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Views for rendering device and certificate table listings."""

import abc
from collections.abc import Sequence
from typing import Any, cast

from django.db.models import (
    Case,
    F,
    IntegerField,
    Prefetch,
    QuerySet,
    Value,
    When,
)
from django.http import HttpResponse, HttpResponseRedirect
from django.http.request import HttpRequest
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy
from django.views.generic.list import ListView

from devices.filters import DeviceFilter
from devices.health import APPLICATION_HEALTH_RANKS, DOMAIN_HEALTH_RANKS, credential_health_expression

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from devices.presentation import DeviceHealthPresentationMixin, onboarding_progress, pki_protocols_display
from onboarding.enums import OnboardingStatus
from pki.models import IssuedCredentialModel
from shared.exports import ExportColumn, ExportConfig, ExportMixin
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
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

class AbstractDeviceTableView(
    DeviceHealthPresentationMixin, ExportMixin, PageContextMixin, ListView[DeviceModel], abc.ABC,
):
    """Device Table View."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'devices'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'common_name'
    filterset_class = DeviceFilter

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    @property
    def device_revoke_url_name(self) -> str:
        """Returns the URL name for the device revoke action."""
        return f'{self.page_category}:{self.page_name}_device_revoke'

    @property
    def device_delete_url_name(self) -> str:
        """Returns the URL name for the device delete action."""
        return f'{self.page_category}:{self.page_name}_device_delete'

    def get_export_config(self) -> ExportConfig:
        """Return the CSV export configuration for the device table."""
        return ExportConfig.from_model(
            DeviceModel,
            include=['common_name', 'serial_number', 'domain', 'ip_address', 'created_at'],
            labels={
                'common_name': str(gettext_lazy('Name')),
                'serial_number': str(gettext_lazy('Serial Number')),
                'created_at': str(gettext_lazy('Created At')),
            },
            extra=[
                ExportColumn(
                    key='enrollment',
                    label=str(gettext_lazy('Enrollment Status')),
                    accessor=lambda d: self._get_onboarding_progress(d)['status_label'],
                ),
                ExportColumn(
                    key='pki_protocols',
                    label=str(gettext_lazy('PKI Protocols')),
                    accessor=self._get_pki_protocols,
                ),
                ExportColumn(
                    key='domain_credential',
                    label=str(gettext_lazy('Domain Credential Status')),
                    accessor=lambda d: self._get_domain_credential_status(d)['status_label'],
                ),
                ExportColumn(
                    key='application_certificates',
                    label=str(gettext_lazy('Application Certificate Status')),
                    accessor=lambda d: self._get_application_certificate_status(d)['status_label'],
                ),
            ],
            filename='devices',
        )

    def apply_filters(self, qs: QuerySet[DeviceModel]) -> QuerySet[DeviceModel]:
        """Applies the `DeviceFilter` to the given queryset.

        Args:
            qs: The base queryset to filter.

        Returns:
            The filtered queryset according to GET parameters.
        """
        self.filterset = DeviceFilter(self.request.GET, queryset=qs, reference_time=self.health_as_of)
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

        filter_keys = {
            'common_name',
            'domain',
            'serial_number',
            'created_at_from',
            'created_at_to',
            'enrollment_state',
            'domain_credential_state',
            'application_certificate_state',
            'expired_device',
        }
        context['filters_active'] = any(
            self.request.GET.get(k) for k in filter_keys
        )

        for device in context['devices']:
            device.clm_button = self._get_clm_button_html(device)
            device.pki_protocols = self._get_pki_protocols(device)
            device.onboarding_progress = self._get_onboarding_progress(device)
            device.domain_credential_status = self._get_domain_credential_status(device)
            device.application_certificate_status = self._get_application_certificate_status(device)
        context['create_url'] = f'{self.page_category}:{self.page_name}_create'
        context['new_onboarding_url'] = f'{self.page_category}:{self.page_name}_new_onboarding'
        context['device_revoke_url'] = reverse(self.device_revoke_url_name)
        context['device_delete_url'] = reverse(self.device_delete_url_name)

        return context

    def get_ordering(self) -> str | Sequence[str] | None:
        """Returns the sort parameters as a list.

        Returns:
           The sort parameters, if any. Otherwise the default sort parameter.
        """
        return self.request.GET.getlist('sort', [self.default_sort_param])

    def get_base_queryset(self) -> QuerySet[DeviceModel]:
        """Return the shared base queryset for device list pages."""
        issued_credentials_prefetch = Prefetch(
            'issued_credentials',
            queryset=IssuedCredentialModel.objects.select_related('credential__certificate__revoked_certificate'),
        )
        return (
            self.model.objects.all()
            # This field is not used in the table and has been a migration pain
            # point in partially updated local databases, so we avoid selecting
            # it eagerly here.
            .defer('rfc_4122_uuid')
            .select_related('domain', 'onboarding_config', 'no_onboarding_config')
            .annotate(
                # Normalise the visible states into integer ranks so the table
                # headers can sort the derived badge columns consistently.
                enrollment_sort=Case(
                    When(no_onboarding_config__isnull=False, then=Value(0)),
                    When(onboarding_config__onboarding_status=OnboardingStatus.PENDING, then=Value(1)),
                    When(onboarding_config__onboarding_status=OnboardingStatus.ONBOARDED, then=Value(2)),
                    default=Value(3),
                    output_field=IntegerField(),
                ),
                domain_credential_sort=credential_health_expression(
                    IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
                    as_of=self.health_as_of, state_values=DOMAIN_HEALTH_RANKS,
                ),
                application_certificate_sort=credential_health_expression(
                    IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
                    as_of=self.health_as_of, state_values=APPLICATION_HEALTH_RANKS,
                ),
                onboarding_protocol_sort=Case(
                    When(onboarding_config__isnull=False, then=F('onboarding_config__onboarding_protocol')),
                    default=Value(-1),
                    output_field=IntegerField(),
                ),
                pki_protocols_sort=Case(
                    When(onboarding_config__isnull=False, then=F('onboarding_config__pki_protocols')),
                    When(no_onboarding_config__isnull=False, then=F('no_onboarding_config__pki_protocols')),
                    default=Value(0),
                    output_field=IntegerField(),
                ),
            )
            # The status badges inspect issued credentials in Python. Prefetching
            # them here prevents an N+1 query pattern across the table rows.
            .prefetch_related(issued_credentials_prefetch)
        )

    def _get_clm_button_html(self, record: DeviceModel) -> SafeString:
        """Gets the HTML for the CLM button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            The HTML of the hyperlink for the CLM button.
        """
        if record.device_type == DeviceModel.DeviceType.OPC_UA_GDS_PUSH:
            clm_url = reverse('devices:opc_ua_gds_push_certificate_lifecycle_management', kwargs={'pk': record.pk})
        elif record.device_type == DeviceModel.DeviceType.AGENT_ONE_TO_ONE:
            clm_url = reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': record.pk})
        else:
            clm_url = reverse(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': record.pk}
            )

        return format_html(
            '<a href="{}" class="btn btn-primary tp-table-btn w-100">{}</a>', clm_url, gettext_lazy('Manage')
        )

    def _get_pki_protocols(self, record: DeviceModel) -> str:
        """Return the device's enabled PKI protocol labels."""
        return pki_protocols_display(record)

    def _get_onboarding_progress(self, record: DeviceModel) -> dict[str, Any]:
        """Build enrollment display data with this page's empty-state text."""
        return onboarding_progress(
            record,
            empty_protocols_label='—',
            unconfigured_label=str(gettext_lazy('Unknown')),
            unconfigured_tooltip=str(gettext_lazy('No enrollment or PKI configuration found.')),
        )


class DeviceTableView(AbstractDeviceTableView):
    """Device Table View."""

    template_name = 'devices/devices.html'

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to include generic, OPC UA GDS Push, and 1-to-1 agent devices.

        1-to-1 agents are shown here because the agent IS the device.

        Returns:
            Returns a queryset of DeviceModels filtered by UI filters.
        """
        base_qs = self.get_base_queryset()
        queryset = self.apply_filters(base_qs)
        ordering = self.get_ordering()
        if ordering:
            if isinstance(ordering, str):
                return queryset.order_by(ordering)
            return queryset.order_by(*ordering)
        return queryset
