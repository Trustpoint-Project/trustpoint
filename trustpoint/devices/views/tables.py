"""Views for rendering device and certificate table listings."""

import abc
from collections.abc import Sequence
from datetime import timedelta
from typing import Any, cast

from django.db.models import (
    Case,
    Exists,
    F,
    IntegerField,
    OuterRef,
    Prefetch,
    QuerySet,
    Value,
    When,
)
from django.http import HttpResponse, HttpResponseRedirect
from django.http.request import HttpRequest
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy
from django.views.generic.list import ListView

from devices.filters import DeviceFilter

# noinspection PyUnresolvedReferences
from devices.models import (
    DeviceModel,
)
from onboarding.enums import OnboardingStatus
from pki.models import IssuedCredentialModel
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
        context['device_revoke_url'] = reverse(f'{self.page_category}:{self.page_name}_device_revoke')
        context['device_delete_url'] = reverse(f'{self.page_category}:{self.page_name}_device_delete')

        return context

    def get_ordering(self) -> str | Sequence[str] | None:
        """Returns the sort parameters as a list.

        Returns:
           The sort parameters, if any. Otherwise the default sort parameter.
        """
        return self.request.GET.getlist('sort', [self.default_sort_param])

    def get_base_queryset(self) -> QuerySet[DeviceModel]:
        """Return the shared base queryset for device list pages."""
        now = timezone.now()
        next_7_days = now + timedelta(days=7)
        # Correlated subqueries used to derive sortable device-state annotations
        # directly in SQL. That keeps sorting/pagination database-backed instead
        # of re-sorting the current page in Python after rendering.
        domain_credentials = IssuedCredentialModel.objects.filter(
            device_id=OuterRef('pk'),
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
            credential__certificate__isnull=False,
        )
        application_credentials = IssuedCredentialModel.objects.filter(
            device_id=OuterRef('pk'),
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
            credential__certificate__isnull=False,
        )
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
                # Boolean existence checks reused by the later sort annotations.
                has_domain_credential=Exists(domain_credentials),
                has_valid_domain_credential=Exists(
                    domain_credentials.filter(
                        credential__certificate__revoked_certificate__isnull=True,
                        credential__certificate__not_valid_after__gt=next_7_days,
                    )
                ),
                has_expiring_domain_credential=Exists(
                    domain_credentials.filter(
                        credential__certificate__revoked_certificate__isnull=True,
                        credential__certificate__not_valid_after__gt=now,
                        credential__certificate__not_valid_after__lte=next_7_days,
                    )
                ),
                has_application_certificate=Exists(application_credentials),
                has_active_application_certificate=Exists(
                    application_credentials.filter(
                        credential__certificate__revoked_certificate__isnull=True,
                        credential__certificate__not_valid_after__gt=now,
                    )
                ),
                domain_credential_sort=Case(
                    When(has_domain_credential=False, then=Value(0)),
                    When(has_valid_domain_credential=True, then=Value(1)),
                    When(has_expiring_domain_credential=True, then=Value(2)),
                    default=Value(3),
                    output_field=IntegerField(),
                ),
                application_certificate_sort=Case(
                    When(has_application_certificate=False, then=Value(0)),
                    When(has_active_application_certificate=True, then=Value(1)),
                    default=Value(2),
                    output_field=IntegerField(),
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

    def _get_onboarding_progress(self, record: DeviceModel) -> dict[str, Any]:
        """Builds structured progress data for the enrollment column."""
        if record.onboarding_config:
            cfg = record.onboarding_config
            is_onboarded = cfg.onboarding_status == OnboardingStatus.ONBOARDED
            status_key = 'onboarded' if is_onboarded else 'pending'
            status_label = str(gettext_lazy('Onboarded') if is_onboarded else gettext_lazy('Pending'))
            onboarding_protocol = str(cfg.get_onboarding_protocol_display())
            pki_labels = [str(p.label) for p in cfg.get_pki_protocols()]
            none_str = str(gettext_lazy('None'))
            pki_list = ''.join(f'<li>{p}</li>' for p in pki_labels) if pki_labels else f'<li>{none_str}</li>'
            tooltip = (
                f'<strong>{gettext_lazy("Onboarding Protocol")}:</strong> {onboarding_protocol}<br>'
                f'<strong>{gettext_lazy("Status")}:</strong> {status_label}<br>'
                f'<strong>{gettext_lazy("PKI Protocols")}:</strong>'
                f'<ul class="mb-0 ps-3 mt-1">{pki_list}</ul>'
            )
        elif record.no_onboarding_config:
            pki_labels = [str(p.label) for p in record.no_onboarding_config.get_pki_protocols()]
            none_str = str(gettext_lazy('None'))
            pki_list = ''.join(f'<li>{p}</li>' for p in pki_labels) if pki_labels else f'<li>{none_str}</li>'
            status_key = 'no-onboarding'
            status_label = str(gettext_lazy('No onboarding'))
            onboarding_protocol = '—'
            tooltip = (
                f'<strong>{gettext_lazy("Enrollment")}:</strong> {gettext_lazy("No onboarding")}<br>'
                f'<strong>{gettext_lazy("PKI Protocols")}:</strong>'
                f'<ul class="mb-0 ps-3 mt-1">{pki_list}</ul>'
            )
        else:
            status_key = 'none'
            status_label = str(gettext_lazy('Unknown'))
            onboarding_protocol = '—'
            pki_labels = []
            tooltip = str(gettext_lazy('No enrollment or PKI configuration found.'))

        pki_protocols = ', '.join(pki_labels) if pki_labels else '—'

        return {
            'status_key': status_key,
            'status_label': status_label,
            'tooltip': tooltip,
            'onboarding_protocol': onboarding_protocol,
            'pki_protocols': pki_protocols,
        }

    @staticmethod
    def _format_datetime_for_tooltip(value: Any) -> str:
        if not value:
            return '—'
        return timezone.localtime(value).strftime('%Y-%m-%d %H:%M')

    @staticmethod
    def _get_certificates_for_type(
        record: DeviceModel,
        credential_type: IssuedCredentialModel.IssuedCredentialType,
    ) -> list[Any]:
        # `issued_credentials` is prefetched in `get_base_queryset()`, so this
        # loop stays in memory while building the badge text/tooltips.
        certificates = []
        for issued_credential in record.issued_credentials.all():
            if issued_credential.issued_credential_type != credential_type:
                continue

            certificate = getattr(issued_credential.credential, 'certificate', None)
            if certificate is not None:
                certificates.append(certificate)

        return certificates

    def _get_domain_credential_status(self, record: DeviceModel) -> dict[str, str]:
        """Build the domain-credential state for the device table."""
        now = timezone.now()
        next_7_days = now + timedelta(days=7)
        certificates = self._get_certificates_for_type(
            record, IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
        )

        if not certificates:
            return {
                'status_key': 'none',
                'status_label': str(gettext_lazy('None')),
                'tooltip': str(gettext_lazy('No domain credential issued.')),
            }

        active_certificates = [cert for cert in certificates if not hasattr(cert, 'revoked_certificate')]
        valid_certificates = [cert for cert in active_certificates if cert.not_valid_after > next_7_days]

        if valid_certificates:
            next_expiry = min(cert.not_valid_after for cert in active_certificates if cert.not_valid_after > now)
            return {
                'status_key': 'valid',
                'status_label': str(gettext_lazy('Valid')),
                'tooltip': (
                    f'<strong>{gettext_lazy("Certificates")}:</strong> {len(certificates)}<br>'
                    f'<strong>{gettext_lazy("Next expiry")}:</strong> '
                    f'{self._format_datetime_for_tooltip(next_expiry)}'
                ),
            }

        expiring_certs = [cert for cert in active_certificates if cert.not_valid_after > now]
        if expiring_certs:
            next_expiry = min(cert.not_valid_after for cert in expiring_certs)
            return {
                'status_key': 'expiring',
                'status_label': str(gettext_lazy('Expiring')),
                'tooltip': (
                    f'<strong>{gettext_lazy("Certificates")}:</strong> {len(certificates)}<br>'
                    f'<strong>{gettext_lazy("Next expiry")}:</strong> '
                    f'{self._format_datetime_for_tooltip(next_expiry)}'
                ),
            }

        latest_expiry = max(cert.not_valid_after for cert in certificates)
        return {
            'status_key': 'expired',
            'status_label': str(gettext_lazy('Expired')),
            'tooltip': (
                f'<strong>{gettext_lazy("Certificates")}:</strong> {len(certificates)}<br>'
                f'<strong>{gettext_lazy("Latest expiry")}:</strong> '
                f'{self._format_datetime_for_tooltip(latest_expiry)}'
            ),
        }

    def _get_application_certificate_status(self, record: DeviceModel) -> dict[str, str]:
        """Build the application-certificate state for the device table."""
        now = timezone.now()
        certificates = self._get_certificates_for_type(
            record, IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL
        )

        if not certificates:
            return {
                'status_key': 'none',
                'status_label': str(gettext_lazy('None')),
                'tooltip': str(gettext_lazy('No application certificates issued.')),
            }

        active_certificates = [
            cert for cert in certificates
            if not hasattr(cert, 'revoked_certificate') and cert.not_valid_after > now
        ]
        if active_certificates:
            next_expiry = min(cert.not_valid_after for cert in active_certificates)
            return {
                'status_key': 'active',
                'status_label': str(gettext_lazy('Active')),
                'tooltip': (
                    f'<strong>{gettext_lazy("Certificates")}:</strong> {len(certificates)}<br>'
                    f'<strong>{gettext_lazy("Next expiry")}:</strong> '
                    f'{self._format_datetime_for_tooltip(next_expiry)}'
                ),
            }

        latest_expiry = max(cert.not_valid_after for cert in certificates)
        return {
            'status_key': 'expired',
            'status_label': str(gettext_lazy('Expired')),
            'tooltip': (
                f'<strong>{gettext_lazy("Certificates")}:</strong> {len(certificates)}<br>'
                f'<strong>{gettext_lazy("Latest expiry")}:</strong> '
                f'{self._format_datetime_for_tooltip(latest_expiry)}'
            ),
        }


class DeviceTableView(AbstractDeviceTableView):
    """Device Table View."""

    template_name = 'devices/devices.html'

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to include all device types (Generic, OPC UA GDS Push) and filtered by UI filters.

        Returns:
            Returns a queryset of all DeviceModels (excluding OPC UA GDS), filtered by UI filters.
        """
        base_qs = self.get_base_queryset().exclude(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS
        )
        queryset = self.apply_filters(base_qs)
        ordering = self.get_ordering()
        if ordering:
            if isinstance(ordering, str):
                return queryset.order_by(ordering)
            return queryset.order_by(*ordering)
        return queryset


class OpcUaGdsTableView(DeviceTableView):
    """Table View for devices where opc_ua_gds is True."""

    template_name = 'devices/opc_ua_gds.html'

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to only include devices which are of OPC-UA GDS type and filtered by UI filters.

        Returns:
            Returns a queryset of all DeviceModels which are of OPC-UA GDS type, filtered by UI filters.
        """
        base_qs = self.get_base_queryset().filter(
            device_type=DeviceModel.DeviceType.OPC_UA_GDS
        )
        queryset = self.apply_filters(base_qs)
        ordering = self.get_ordering()
        if ordering:
            if isinstance(ordering, str):
                return queryset.order_by(ordering)
            return queryset.order_by(*ordering)
        return queryset
