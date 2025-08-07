"""This module contains all views concerning the devices application."""

from __future__ import annotations

import abc
import datetime
import io
from typing import TYPE_CHECKING, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.http import FileResponse, Http404, HttpResponse, HttpResponseBase, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext
from django.views.generic.base import RedirectView, TemplateView
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel
from trustpoint_core.archiver import Archiver
from trustpoint_core.serializer import CredentialFileFormat
from util.mult_obj_views import get_primary_keys_from_str_as_list_of_ints

from devices.forms import (
    ApplicationCertProfileSelectForm,
    BrowserLoginForm,
    ClmDeviceModelNoOnboardingForm,
    ClmDeviceModelOnboardingForm,
    CredentialDownloadForm,
    DeleteDevicesForm,
    IssueDomainCredentialForm,
    IssueOpcUaClientCredentialForm,
    IssueOpcUaServerCredentialForm,
    IssueTlsClientCredentialForm,
    IssueTlsServerCredentialForm,
    NoOnboardingCreateForm,
    OnboardingCreateForm,
    RevokeDevicesForm,
    RevokeIssuedCredentialForm,
)
from devices.issuer import (
    LocalDomainCredentialIssuer,
    LocalTlsClientCredentialIssuer,
    LocalTlsServerCredentialIssuer,
    OpcUaClientCredentialIssuer,
    OpcUaServerCredentialIssuer,
)
from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
    NoOnboardingPkiProtocol,
    OnboardingPkiProtocol,
    OnboardingProtocol,
    OnboardingStatus,
    RemoteDeviceCredentialDownloadModel,
)
from devices.revocation import DeviceCredentialRevocation
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)
from trustpoint.settings import UIConfig

if TYPE_CHECKING:
    import ipaddress
    from collections.abc import Sequence
    from typing import Any

    from django.http.request import HttpRequest
    from django.utils.safestring import SafeString

    # noinspection PyUnresolvedReferences
    from devices.forms import BaseCredentialForm

    # noinspection PyUnresolvedReferences
    from devices.issuer import BaseTlsCredentialIssuer

DeviceWithoutDomainErrorMsg = _('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = _('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = _('No active trustpoint TLS server credential found.')

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

# This must be removed in the future makeing use of the profile engine
ALLOWED_APP_CRED_PROFILES = [
    {'profile': 'tls-server', 'label': 'TLS-Server Certficate'},
    {'profile': 'tls-client', 'label': 'TLS-Client Certificate'},
    {'profile': 'opcua-server', 'label': 'OPC-UA-Server Certificate'},
    {'profile': 'opcua-client', 'label': 'OPC-UA-Client Certificate'},
]

# -------------------------------------------------- Main Table Views --------------------------------------------------


class AbstractDeviceTableView(PageContextMixin, ListView[DeviceModel], abc.ABC):
    """Device Table View."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'devices'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'common_name'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

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

        for device in context['devices']:
            device.clm_button = self._get_clm_button_html(device)
            device.detail_button = self._get_details_button_html(device)
            device.pki_protocols = self._get_pki_protocols(device)
        context['create_url'] = f'{self.page_category}:{self.page_name}_create'
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
        clm_url = reverse(
            f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': record.pk}
        )

        return format_html('<a href="{}" class="btn btn-primary tp-table-btn w-100">{}</a>', clm_url, _('Manage'))

    def _get_details_button_html(self, record: DeviceModel) -> SafeString:
        """Gets the HTML for the Details button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            the HTML of the hyperlink for the detail button.
        """
        details_url = reverse(f'devices:{self.page_name}_details', kwargs={'pk': record.pk})
        return format_html('<a href="{}" class="btn btn-primary tp-table-btn w-100">{}</a>', details_url, _('Details'))

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
        """Filter queryset to only include devices which are of generic type.

        Returns:
            Returns a queryset of all DeviceModels which are of generic type.
        """
        return super(ListView, self).get_queryset().filter(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)


class OpcUaGdsTableView(DeviceTableView):
    """Table View for devices where opc_ua_gds is True."""

    template_name = 'devices/opc_ua_gds.html'

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Filter queryset to only include devices which are of OPC-UA GDS type.

        Returns:
            Returns a queryset of all DeviceModels which are of OPC-UA GDS type.
        """
        return super(ListView, self).get_queryset().filter(device_type=DeviceModel.DeviceType.OPC_UA_GDS)


# ------------------------------------------------- Device Detail View -------------------------------------------------


class AbstractDeviceDetailsView(PageContextMixin, DetailView[DeviceModel], abc.ABC):
    """Device Details View."""

    http_method_names = ('get',)

    model = DeviceModel
    template_name = 'devices/details.html'
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_details_url'] = f'devices:{self.page_name}'
        return context


class DeviceDetailsView(AbstractDeviceDetailsView):
    """Details view for common devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaDeviceDetailsView(AbstractDeviceDetailsView):
    """Details view for OPC UA devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


# ------------------------------------------------- Device Create View -------------------------------------------------


class AbstractCreateChooseOnboaringView(TemplateView):
    """Abstract view for choosing if the new device shall be onboarded or not."""

    http_method_names = ('get',)
    template_name = 'devices/create_choose_onboarding.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'devices:{self.page_name}'
        context['use_onboarding_url'] = f'{self.page_category}:{self.page_name}_create_onboarding'
        context['use_no_onboarding_url'] = f'{self.page_category}:{self.page_name}_create_no_onboarding'
        return context


class DeviceCreateChooseOnboardingView(AbstractCreateChooseOnboaringView):
    """View for choosing if the new device shall be onboarded or not."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsCreateChooseOnboardingView(AbstractCreateChooseOnboaringView):
    """View for choosing if the new OPC UA GDS shall be onboarded or not."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractCreateNoOnboardingView(PageContextMixin, FormView[NoOnboardingCreateForm]):
    """asdfds."""

    http_method_names = ('get', 'post')

    form_class = NoOnboardingCreateForm
    template_name = 'devices/create.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{self.page_category}:{self.page_name}'
        return context

    def form_valid(self, form: NoOnboardingCreateForm) -> HttpResponse:
        """Saves the form / creates the device model object.

        Args:
            form: The valid form.

        Returns:
            The HTTP Response to be returned.
        """
        if self.page_name == DEVICES_PAGE_DEVICES_SUBCATEGORY:
            self.object = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        else:
            self.object = form.save(device_type=DeviceModel.DeviceType.OPC_UA_GDS)
        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        return str(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': self.object.id}
            )
        )


class DeviceCreateNoOnboardingView(AbstractCreateNoOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsCreateNoOnboardingView(AbstractCreateNoOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractCreateOnboardingView(PageContextMixin, FormView[OnboardingCreateForm]):
    """asdfds."""

    http_method_names = ('get', 'post')

    form_class = OnboardingCreateForm
    template_name = 'devices/create.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the cancel url href according to the subcategory.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the devices page.
        """
        context = super().get_context_data(**kwargs)
        context['cancel_create_url'] = f'{self.page_category}:{self.page_name}'
        return context

    def form_valid(self, form: OnboardingCreateForm) -> HttpResponse:
        """Saves the form / creates the device model object.

        Args:
            form: The valid form.

        Returns:
            The HTTP Response to be returned.
        """
        if self.page_name == DEVICES_PAGE_DEVICES_SUBCATEGORY:
            self.object = form.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
        else:
            self.object = form.save(device_type=DeviceModel.DeviceType.OPC_UA_GDS)
        return super().form_valid(form)

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        return str(
            reverse_lazy(
                f'{self.page_category}:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': self.object.id}
            )
        )


class DeviceCreateOnboardingView(AbstractCreateOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsCreateOnboardingView(AbstractCreateOnboardingView):
    """Create form view for the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


# ------------------------------------------ Certificate Lifecycle Management ------------------------------------------


class AbstractCertificateLifecycleManagementSummaryView(PageContextMixin, DetailView[DeviceModel], abc.ABC):
    """This is the CLM summary view in the devices section."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    template_name = 'devices/credentials/certificate_lifecycle_management.html'
    context_object_name = 'device'

    default_sort_param = 'common_name'
    issued_creds_qs: QuerySet[IssuedCredentialModel]
    domain_credentials_qs: QuerySet[IssuedCredentialModel]
    application_credentials_qs: QuerySet[IssuedCredentialModel]

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_issued_creds_qs(self) -> QuerySet[IssuedCredentialModel]:
        """Gets a sorted queryset of all IssuedCredentialModels.

        Returns:
            Sorted queryset of all IssuedCredentialModels.
        """
        issued_creds_qs = IssuedCredentialModel.objects.all()

        # Get sort parameter (e.g., "name" or "-name")
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        return issued_creds_qs.order_by(sort_param)

    def get_domain_credentials_qs(self) -> QuerySet[IssuedCredentialModel]:
        """Gets a sorted queryset of all IssuedCredentialModels that are domain credentials.

        self.get_issued_creds_qs() must be called first!

        Returns:
            Sorted queryset of all IssuedCredentialModels that are domain credentials
        """
        return self.issued_creds_qs.filter(
            Q(device=self.object)
            & Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value)
        )

    def get_application_credentials_qs(self) -> QuerySet[IssuedCredentialModel]:
        """Gets a sorted queryset of all IssuedCredentialModels that are application credentials.

            self.get_issued_creds_qs() must be called first!

        Returns:
            Sorted queryset of all IssuedCredentialModels that are application credentials.
        """
        return self.issued_creds_qs.filter(
            Q(device=self.object)
            & Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value)
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the paginator and credential details to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the clm summary page.
        """
        self.issued_creds_qs = self.get_issued_creds_qs()
        self.domain_credentials_qs = self.get_domain_credentials_qs()
        self.application_credentials_qs = self.get_application_credentials_qs()
        context = super().get_context_data(**kwargs)

        context['domain_credentials'] = self.domain_credentials_qs
        context['application_credentials'] = self.application_credentials_qs

        paginator_domain = Paginator(self.domain_credentials_qs, UIConfig.paginate_by)
        page_number_domain = self.request.GET.get('page', 1)
        context['domain_credentials'] = paginator_domain.get_page(page_number_domain)
        context['is_paginated'] = paginator_domain.num_pages > 1

        paginator_application = Paginator(self.application_credentials_qs, 3)
        page_number_application = self.request.GET.get('page-a', 1)
        context['application_credentials'] = paginator_application.get_page(page_number_application)
        context['is_paginated_a'] = paginator_application.num_pages > 1

        for cred in context['domain_credentials']:
            cred.expires_in = self._get_expires_in(cred)
            cred.expiration_date = cast('datetime.datetime', cred.credential.certificate.not_valid_after)
            cred.revoke = self._get_revoke_button_html(cred)

        for cred in context['application_credentials']:
            cred.expires_in = self._get_expires_in(cred)
            cred.expiration_date = cast('datetime.datetime', cred.credential.certificate.not_valid_after)
            cred.revoke = self._get_revoke_button_html(cred)

        context['main_url'] = f'devices:{self.page_name}'
        context['issue_app_cred_no_onboarding_url'] = (
            f'devices:{self.page_name}_no_onboarding_clm_issue_application_credential'
        )

        context['download_url'] = f'{self.page_category}:{self.page_name}_download'

        context['help_dispatch_domain_url'] = f'{self.page_category}:{self.page_name}_help_dispatch_domain'
        context['help_dispatch_device_type_url'] = f'{self.page_category}:{self.page_name}_help_dispatch_domain'

        context['pki_protocols'] = self._get_pki_protocols(self.object)

        context['OnboardingProtocol'] = OnboardingProtocol
        context['OnboardingPkiProtocol'] = OnboardingPkiProtocol
        context['NoOnboardingPkiProtocol'] = NoOnboardingPkiProtocol
        context['OnboardingStatus'] = OnboardingStatus

        context['device_form'] = self.get_device_form()

        return context

    def get_onboarding_initial(self) -> dict[str, Any]:
        """Gets the initial values for onboarding.

        Returns:
            Initial values for onboarding.
        """
        if not self.object.onboarding_config:
            err_msg = _('The device does not have onboarding configured.')
            raise ValueError(err_msg)
        return {
            'common_name': self.object.common_name,
            'serial_number': self.object.serial_number,
            'domain': self.object.domain,
            'onboarding_protocol': self.object.onboarding_config.onboarding_protocol,
            'onboarding_status': OnboardingStatus(self.object.onboarding_config.onboarding_status).label,
            'pki_protocol_cmp': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.CMP),
            'pki_protocol_est': self.object.onboarding_config.has_pki_protocol(OnboardingPkiProtocol.EST),
        }

    def get_no_onboarding_initial(self) -> dict[str, Any]:
        """Gets the initial values for no onboarding.

        Returns:
            Initial values for no onboarding.
        """
        if not self.object.no_onboarding_config:
            err_msg = _('The object has onboarding configured.')
            raise ValueError(err_msg)
        return {
            'common_name': self.object.common_name,
            'serial_number': self.object.serial_number,
            'domain': self.object.domain,
            'pki_protocol_cmp': self.object.no_onboarding_config.has_pki_protocol(
                NoOnboardingPkiProtocol.CMP_SHARED_SECRET),
            'pki_protocol_est': self.object.no_onboarding_config.has_pki_protocol(
                NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD),
            'pki_protocol_manual': self.object.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.MANUAL)
        }

    def get_onboarding_form(self) -> ClmDeviceModelOnboardingForm:
        """Gets the form for onboarding.

        Returns:
            The onboarding form.
        """
        return ClmDeviceModelOnboardingForm(initial=self.get_onboarding_initial(), instance=self.object)

    def get_no_onboarding_form(self) -> ClmDeviceModelNoOnboardingForm:
        """Gets the form for no onboarding.

        Returns:
            The no onboarding form.
        """
        if self.request.method == 'POST':
            return ClmDeviceModelNoOnboardingForm(self.request.POST, instance=self.object)
        return ClmDeviceModelNoOnboardingForm(initial=self.get_no_onboarding_initial(), instance=self.object)

    def get_device_form(self) -> ClmDeviceModelOnboardingForm | ClmDeviceModelNoOnboardingForm:
        """Gets the device Form for onboarding or no onboarding.

        Returns:
            The required form.
        """
        if self.object.onboarding_config:
            return self.get_onboarding_form()
        return self.get_no_onboarding_form()

    @staticmethod
    def _get_expires_in(record: IssuedCredentialModel) -> str:
        """Gets the remaining time until the credential expires as human-readable string.

        Args:
            record: The corresponding IssuedCredentialModel.

        Returns:
            The remaining time until the credential expires as human-readable string.
        """
        if record.credential.certificate.certificate_status != CertificateModel.CertificateStatus.OK:
            return str(record.credential.certificate.certificate_status.label)
        now = datetime.datetime.now(datetime.UTC)
        expire_timedelta = record.credential.certificate.not_valid_after - now
        days = expire_timedelta.days
        hours, remainder = divmod(expire_timedelta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f'{days} days, {hours}:{minutes:02d}:{seconds:02d}'

    def _get_revoke_button_html(self, record: IssuedCredentialModel) -> str:
        """Gets the HTML for the revoke button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            The HTML of the hyperlink for the revoke button.
        """
        if record.credential.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED:
            return format_html('<a class="btn btn-danger tp-table-btn w-100 disabled">{}</a>', _('Revoked'))
        url = reverse(f'{self.page_category}:{self.page_name}_credential_revoke', kwargs={'pk': record.pk})
        return format_html('<a href="{}" class="btn btn-danger tp-table-btn w-100">{}</a>', url, _('Revoke'))

    def _get_pki_protocols(self, record: DeviceModel) -> str:
        if record.onboarding_config:
            return ', '.join([str(p.label) for p in record.onboarding_config.get_pki_protocols()])

        if record.no_onboarding_config:
            return ', '.join([str(p.label) for p in record.no_onboarding_config.get_pki_protocols()])

        return ''

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        self.object = self.get_object()

        __, ___, ____ = request, args, kwargs

        form: ClmDeviceModelOnboardingForm | ClmDeviceModelNoOnboardingForm
        if self.object.onboarding_config:
            form = ClmDeviceModelOnboardingForm(self.request.POST, instance=self.object)
        else:
            form = ClmDeviceModelNoOnboardingForm(self.request.POST, instance=self.object)

        if form.is_valid():
            form.save()

        context = self.get_context_data(object=self.object)
        return self.render_to_response(context)

class DeviceCertificateLifecycleManagementSummaryView(AbstractCertificateLifecycleManagementSummaryView):
    """Certificate Lifecycle Management Summary View for devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsCertificateLifecycleManagementSummaryView(AbstractCertificateLifecycleManagementSummaryView):
    """Certificate Lifecycle Management Summary View for OPC UA Devcies."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


#  ------------------------------ Certificate Lifecycle Management - Credential Issuance -------------------------------


class AbstractNoOnboardingIssueNewApplicationCredentialView(DetailView[DeviceModel]):
    """abc."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_credential.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the sections to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'
        context['heading'] = 'Issue New Application Credential'
        sections = []

        if not self.object.no_onboarding_config:
            err_msg = _('Device is configured for onboarding')
            raise ValueError(err_msg)

        sections.append({
            'heading': _('CMP with OpenSSL (shared-secret)'),
            'description': _(
                'This option will guide you through all steps and commands that are '
                'required to issue a new application certificate using CMP with OpenSSL using a shared-secret (HMAC).'),
            'protocol': 'cmp-shared-secret',
            'enabled': self.object.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.CMP_SHARED_SECRET),
        })

        sections.append({
            'heading': _('EST with OpenSSL and curL (username & password)'),
            'description': _(
                'This option will guide you through all steps and commands that are '
                'required to issue a new application certificate using EST using OpenSSL and curL.'
            ),
            'protocol': 'est-username-password',
            'enabled': self.object.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD),
        })


        sections.append({
            'heading': _('Manual Issuance'),
            'description': _(
                'This option will allow you to issue a new domain credential on the Trustpoint. '
                'The domain credential can then be downloaded for manual injection into the device, '
                'e.g., using a USB-stick.'
            ),
            'protocol': 'manual',
            'enabled': self.object.no_onboarding_config.has_pki_protocol(NoOnboardingPkiProtocol.MANUAL),
        })


        context['sections'] = sections
        context['profile_select_url'] = (
            f'{self.page_category}:{self.page_name}_no_onboarding_clm_issue_application_credential_profile_select'
        )

        return context


class DeviceNoOnboardingIssueNewApplicationCredentialView(AbstractNoOnboardingIssueNewApplicationCredentialView):
    """abc."""
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingIssueNewApplicationCredentialView(AbstractNoOnboardingIssueNewApplicationCredentialView):
    """abc."""
    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractNoOnboardingProfileSelectHelpView(DetailView[DeviceModel]):
    """abc."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/profile_select.html'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the sections to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        context['cert_profiles'] = ALLOWED_APP_CRED_PROFILES

        protocol = self.kwargs.get('protocol')

        context['manual_options'] = []
        if protocol == 'cmp-shared-secret':
            help_url = f'{self.page_category}:{self.page_name}_help_no_onboarding_cmp_shared_secret'
        elif protocol == 'est-username-password':
            help_url = f'{self.page_category}:{self.page_name}_help_no_onboarding_est_username_password'
        elif protocol == 'manual':
            help_url = None
            context['manual_options'] = [
                {
                    'profile': 'TLS-Client Certificate',
                    'url': (
                        f'{self.page_category}:{self.page_name}'
                        '_certificate_lifecycle_management-issue_tls_client_credential')
                },
                {
                    'profile': 'TLS-Server Certificate',
                    'url': (
                        f'{self.page_category}:{self.page_name}'
                        '_certificate_lifecycle_management-issue_tls_server_credential')
                },
                {
                    'profile': 'OPC-UA-Client Certificate',
                    'url': (
                        f'{self.page_category}:{self.page_name}'
                        '_certificate_lifecycle_management-issue_opc_ua_client_credential')
                },
                {
                    'profile': 'OPC-UA-Client Certificate',
                    'url': (
                        f'{self.page_category}:{self.page_name}'
                        '_certificate_lifecycle_management-issue_opc_ua_server_credential')
                },
            ]
        else:
            err_msg = _('Unknown protocol found.')
            raise Http404(err_msg)

        context['help_url'] = help_url


        return context


class DeviceNoOnboardingProfileSelectHelpView(AbstractNoOnboardingProfileSelectHelpView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingProfileSelectHelpView(AbstractNoOnboardingProfileSelectHelpView):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractIssueCredentialView[FormClass: BaseCredentialForm, IssuerClass: BaseTlsCredentialIssuer](
    PageContextMixin, DetailView[DeviceModel]
):
    """Base view for all credential issuance views."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'

    form_class: type[FormClass]
    issuer_class: type[IssuerClass]
    friendly_name: str

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the form to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        if 'form' not in kwargs:
            context['form'] = self.form_class(**self.get_form_kwargs())

        context['clm_url'] = f'devices:{self.page_name}_certificate_lifecycle_management'
        return context

    def get_form_kwargs(self) -> dict[str, Any]:
        """This method ads the concerning device model to the form kwargs and returns them.

        Returns:
            The form kwargs including the concerning device model.
        """
        if self.object.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        form_kwargs = {
            'initial': self.issuer_class.get_fixed_values(device=self.object, domain=self.object.domain),
            'prefix': None,
            'device': self.object,
        }

        if self.request.method == 'POST':
            form_kwargs.update({'data': self.request.POST})

        return form_kwargs

    @abc.abstractmethod
    def issue_credential(self, device: DeviceModel, cleaned_data: dict[str, Any]) -> IssuedCredentialModel:
        """Abstract method to issue a credential.

        Args:
            device: The device to be associated with the new credential.
            cleaned_data: The validated form data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """

    def post(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Adds the object model to the instance and forwards to super().post().

        Args:
            _request: The Django request object is only used implicitly through self.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            The HttpResponseBase object returned by super().post().
        """
        self.object = self.get_object()
        form = self.form_class(**self.get_form_kwargs())

        if form.is_valid():
            credential = self.issue_credential(device=self.object, cleaned_data=form.cleaned_data)
            messages.success(
                self.request, f'Successfully issued {self.friendly_name} for device {credential.device.common_name}'
            )
            return HttpResponseRedirect(
                reverse_lazy(
                    f'devices:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': self.get_object().id}
                )
            )

        return self.render_to_response(self.get_context_data(form=form))


class AbstractIssueDomainCredentialView(
    AbstractIssueCredentialView[IssueDomainCredentialForm, LocalDomainCredentialIssuer]
):
    """Base view for issuing domain credentials."""

    form_class = IssueDomainCredentialForm
    template_name = 'devices/credentials/issue_domain_credential.html'
    issuer_class = LocalDomainCredentialIssuer
    friendly_name = 'Domain Credential'

    def issue_credential(self, device: DeviceModel, cleaned_data: dict[str, Any]) -> IssuedCredentialModel:
        """Issue a domain credential for the device.

        Args:
            device: The device to issue the credential for.
            cleaned_data: The validated form data.

        Returns:
            The issued credential model.
        """
        __ = cleaned_data

        if device.domain is None:
            err_msg = _('Device has no domain configured.')
            raise Http404(err_msg)

        issuer = self.issuer_class(device=device, domain=device.domain)
        return issuer.issue_domain_credential()


class DeviceIssueDomainCredentialView(AbstractIssueDomainCredentialView):
    """View for issuing domain credentials for devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssueDomainCredentialView(AbstractIssueDomainCredentialView):
    """View for issuing domain credentials for OPC-UA GDS devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractIssueTlsClientCredentialView(
    AbstractIssueCredentialView[IssueTlsClientCredentialForm, LocalTlsClientCredentialIssuer]
):
    """View to issue a new TLS client credential."""

    form_class = IssueTlsClientCredentialForm
    issuer_class = LocalTlsClientCredentialIssuer
    friendly_name = 'TLS client credential'

    page_name: str

    def issue_credential(self, device: DeviceModel, cleaned_data: dict[str, Any]) -> IssuedCredentialModel:
        """Issues an TLS client credential.

        Args:
            device: The device to be associated with the new credential.
            cleaned_data: The validated form data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """
        common_name = cast('str', cleaned_data.get('common_name'))
        validity = cast('int', cleaned_data.get('validity'))
        if not device.domain:
            raise Http404(DeviceWithoutDomainErrorMsg)
        issuer = self.issuer_class(device=device, domain=device.domain)

        return issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity)


class DeviceIssueTlsClientCredentialView(AbstractIssueTlsClientCredentialView):
    """Issue a new TLS client credential within the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssueTlsClientCredentialView(AbstractIssueTlsClientCredentialView):
    """Issue a new TLS client credential within the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractIssueTlsServerCredentialView(
    AbstractIssueCredentialView[IssueTlsServerCredentialForm, LocalTlsServerCredentialIssuer]
):
    """View to issue a new TLS server credential."""

    form_class = IssueTlsServerCredentialForm
    issuer_class = LocalTlsServerCredentialIssuer
    friendly_name = 'TLS server credential'

    def issue_credential(self, device: DeviceModel, cleaned_data: dict[str, Any]) -> IssuedCredentialModel:
        """Issues an TLS server credential.

        Args:
            device: The device to be associated with the new credential.
            cleaned_data: The validated form data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """
        common_name = cast('str', cleaned_data.get('common_name'))
        if not common_name:
            err_msg = 'Common name is missing. Cannot issue credential.'
            raise Http404(err_msg)
        if not device.domain:
            raise Http404(DeviceWithoutDomainErrorMsg)
        issuer = self.issuer_class(device=device, domain=device.domain)
        return issuer.issue_tls_server_credential(
            common_name=common_name,
            ipv4_addresses=cast('list[ipaddress.IPv4Address]', cleaned_data.get('ipv4_addresses')),
            ipv6_addresses=cast('list[ipaddress.IPv6Address]', cleaned_data.get('ipv6_addresses')),
            domain_names=cast('list[str]', cleaned_data.get('domain_names')),
            san_critical=False,
            validity_days=cast('int', cleaned_data.get('validity')),
        )


class DeviceIssueTlsServerCredentialView(AbstractIssueTlsServerCredentialView):
    """Issues a TLS server credenital within the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssueTlsServerCredentialView(AbstractIssueTlsServerCredentialView):
    """Issues a TLS server credenital within the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

class AbstractIssueOpcUaClientCredentialView(
    AbstractIssueCredentialView[IssueOpcUaClientCredentialForm, OpcUaClientCredentialIssuer]
):
    """View to issue a new OPC UA client credential."""

    form_class = IssueOpcUaClientCredentialForm
    issuer_class = OpcUaClientCredentialIssuer
    friendly_name = 'OPC UA client credential'

    def issue_credential(self, device: DeviceModel, cleaned_data: dict[str, Any]) -> IssuedCredentialModel:
        """Issues an OPC UA client credential.

        Args:
            device: The device to be associated with the new credential.
            cleaned_data: The validated form data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """
        if not device.domain:
            raise Http404(DeviceWithoutDomainErrorMsg)
        issuer = self.issuer_class(device=device, domain=device.domain)
        return issuer.issue_opcua_client_credential(
            common_name=cast('str', cleaned_data.get('common_name')),
            application_uri=cast('str', cleaned_data.get('application_uri')),
            validity_days=cast('int', cleaned_data.get('validity')),
        )


class DeviceIssueOpcUaClientCredentialView(AbstractIssueOpcUaClientCredentialView):
    """Issues an OPC UA client credential within the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssueOpcUaClientCredentialView(AbstractIssueOpcUaClientCredentialView):
    """Issues an OPC UA client credential within the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractIssueOpcUaServerCredentialView(
    AbstractIssueCredentialView[IssueOpcUaServerCredentialForm, OpcUaServerCredentialIssuer]
):
    """View to issue a new OPC UA server credential."""

    form_class = IssueOpcUaServerCredentialForm
    issuer_class = OpcUaServerCredentialIssuer
    friendly_name = 'OPC UA server credential'

    def issue_credential(self, device: DeviceModel, cleaned_data: dict[str, Any]) -> IssuedCredentialModel:
        """Issues an OPC UA server credential.

        Args:
            device: The device to be associated with the new credential.
            cleaned_data: The validated form data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """
        common_name = cast('str', cleaned_data.get('common_name'))
        if not common_name:
            err_msg = 'Common name is missing. Cannot issue credential.'
            raise Http404(err_msg)
        if not device.domain:
            raise Http404(DeviceWithoutDomainErrorMsg)
        issuer = self.issuer_class(device=device, domain=device.domain)

        ipv4_addresses: list[ipaddress.IPv4Address] = cleaned_data.get('ipv4_addresses', [])
        ipv6_addresses: list[ipaddress.IPv6Address] = cleaned_data.get('ipv6_addresses', [])
        domain_names: list[str] = cleaned_data.get('domain_names', [])
        validity_days: int = cleaned_data.get('validity', 0)

        return issuer.issue_opcua_server_credential(
            common_name=common_name,
            application_uri=cast('str', cleaned_data.get('application_uri')),
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            domain_names=domain_names,
            validity_days=validity_days,
        )


class DeviceIssueOpcUaServerCredentialView(AbstractIssueOpcUaServerCredentialView):
    """Issues an OPC UA server credential within the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssueOpcUaServerCredentialView(AbstractIssueOpcUaServerCredentialView):
    """Issues an OPC UA server credential within the devices section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


#  -------------------------------- Certificate Lifecycle Management - Token Auth Mixin --------------------------------


class DownloadTokenRequiredAuthenticationMixin:
    """Mixin which checks the token included in the URL for browser download views."""

    credential_download: RemoteDeviceCredentialDownloadModel

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Checks the validity of the token included in the URL for browser download views and redirects if invalid.

        Args:
            request: The django request object.
            *args: Positional arguments passed to super().dispatch().
            **kwargs: Keyword arguments passed to super().dispatch().

        Returns:
            A Django HttpResponseBase object.
        """
        super_dispatch = getattr(super(), 'dispatch', None)
        if not callable(super_dispatch):
            err_msg = 'Internal server error. Failed to get super().dispatch().'
            raise Http404(err_msg)

        token = request.GET.get('token')
        try:
            self.credential_download = RemoteDeviceCredentialDownloadModel.objects.get(
                issued_credential_model=kwargs.get('pk')
            )
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            messages.warning(request, 'Invalid download token.')
            return redirect('devices:browser_login')

        if not token or not self.credential_download.check_token(token):
            messages.warning(request, 'Invalid download token.')
            return redirect('devices:browser_login')

        return cast('HttpResponseBase', super_dispatch(request, *args, **kwargs))


#  ----------------------------------- Certificate Lifecycle Management - Downloads ------------------------------------


class AbstractDownloadPageDispatcherView(PageContextMixin, RedirectView):
    """Redirects depending on the type of credential, that is if a private key is available or not."""

    http_method_names = ('get',)

    model: type[IssuedCredentialModel] = IssuedCredentialModel
    permanent = False

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_redirect_url(self, *_args: Any, **kwargs: Any) -> str:
        """Gets the redirection URL depending on the type credential, that is if a private key is available or not.

        Args:
            *_args: Positional arguments are discarded.
            **kwargs: The pk parameter is retrieved and expected to be there.

        Returns:
            The redirect URL.
        """
        pk = kwargs.get('pk')

        # This can only happen if the path for the URL defined in urls.py does not contain <int:pk>.
        # This would mean we, the dev team, introduced a bug.
        if pk is None or not isinstance(pk, int):
            err_msg = 'An unexpected error occurred. Please see logs for more information.'
            raise Http404(err_msg)

        issued_credential = IssuedCredentialModel.objects.filter(pk=pk).first()
        if issued_credential is None:
            messages.error(
                self.request, 'No credential found for the given primary key. See logs for more information.'
            )
            return reverse(f'devices:{self.page_name}_certificate_lifecycle_management', kwargs={'pk': pk})

        if issued_credential.credential.private_key:
            return reverse(f'devices:{self.page_name}_credential-download', kwargs={'pk': pk})

        return reverse(f'devices:{self.page_name}_certificate-download', kwargs={'pk': pk})


class DeviceDownloadPageDispatcherView(AbstractDownloadPageDispatcherView):
    """Download dispatcher view for the device pages."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsDownloadPageDispatcherView(AbstractDownloadPageDispatcherView):
    """Download dispatcher view for the OPC UA GDS pages."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


# --------------------------------------------- Certificate Download Help ----------------------------------------------


class AbstractCertificateDownloadView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """View for downloading certificates."""

    http_method_names = ('get',)

    model: type[IssuedCredentialModel] = IssuedCredentialModel
    template_name = 'devices/credentials/certificate_download.html'
    context_object_name = 'issued_credential'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the clm_url to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'
        return context


class DeviceCertificateDownloadView(AbstractCertificateDownloadView):
    """Certificate download view for the device pages."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsCertificateDownloadView(AbstractCertificateDownloadView):
    """Certificate download view for the OPC UA GDS pages."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


# ---------------------------------------------- Credential Download Help ----------------------------------------------


class AbstractDeviceBaseCredentialDownloadView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """View to download a password protected application credential in the desired format.

    Inherited by the domain and application credential download views. It is not intended for direct use.
    """

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/credentials/credential_download.html'
    context_object_name = 'credential'

    form_class = CredentialDownloadForm

    is_browser_download = False

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the credential to the context.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        issued_credential = self.object
        credential = issued_credential.credential

        if credential.credential_type != CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL:  # sanity check
            err_msg = 'Credential is not an issued credential.'
            raise Http404(err_msg)

        credential_purpose = IssuedCredentialModel.IssuedCredentialPurpose(
            issued_credential.issued_credential_purpose
        ).label

        domain_credential_value = IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value
        application_credential_value = IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value

        if issued_credential.issued_credential_type == domain_credential_value:
            context['credential_type'] = credential_purpose

        elif issued_credential.issued_credential_type == application_credential_value:
            context['credential_type'] = credential_purpose + ' Credential'

        else:
            err_msg = 'Unknown IssuedCredentialType'
            raise Http404(err_msg)

        context['FileFormat'] = CredentialFileFormat.__members__
        context['is_browser_dl'] = self.is_browser_download
        context['show_browser_dl'] = not self.is_browser_download
        context['issued_credential'] = issued_credential

        if 'form' not in kwargs:
            context['form'] = self.form_class()
        else:
            context['form'] = kwargs['form']

        context['browser_otp_url'] = f'devices:{self.page_name}_browser_otp_view'
        context['clm_url'] = f'devices:{self.page_name}_certificate_lifecycle_management'

        return context

    def post(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to start the download process of the desired file.

        Args:
            form: The valid form including the cleaned data.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        self.object = self.get_object()
        form = self.form_class(self.request.POST)

        if form.is_valid():
            password = form.cleaned_data['password'].encode()

            try:
                file_format = CredentialFileFormat(self.request.POST.get('file_format'))
            except ValueError as exception:
                err_msg = _('Unknown file format.')
                raise Http404(err_msg) from exception

            credential_model = self.object.credential
            credential_serializer = credential_model.get_credential_serializer()

            private_key_serializer = credential_serializer.get_private_key_serializer()
            certificate_serializer = credential_serializer.get_certificate_serializer()
            cert_collection_serializer = credential_serializer.get_additional_certificates_serializer()
            if not private_key_serializer or not certificate_serializer or not cert_collection_serializer:
                raise Http404

            credential_purpose = IssuedCredentialModel.IssuedCredentialPurpose(
                self.object.issued_credential_purpose
            ).label
            credential_type_name = credential_purpose.replace(' ', '-').lower().replace('-credential', '')

            if file_format == CredentialFileFormat.PKCS12:
                file_stream_data = io.BytesIO(credential_serializer.as_pkcs12(password=password))

            elif file_format == CredentialFileFormat.PEM_ZIP:
                file_data = Archiver.archive_zip(
                    data_to_archive={
                        'private_key.pem': private_key_serializer.as_pkcs8_pem(password=password),
                        'certificate.pem': certificate_serializer.as_pem(),
                        'certificate_chain.pem': cert_collection_serializer.as_pem(),
                    }
                )
                file_stream_data = io.BytesIO(file_data)

            elif file_format == CredentialFileFormat.PEM_TAR_GZ:
                file_data = Archiver.archive_tar_gz(
                    data_to_archive={
                        'private_key.pem': private_key_serializer.as_pkcs8_pem(password=password),
                        'certificate.pem': certificate_serializer.as_pem(),
                        'certificate_chain.pem': cert_collection_serializer.as_pem(),
                    }
                )
                file_stream_data = io.BytesIO(file_data)

            else:
                err_msg = _('Unknown file format.')
                raise Http404(err_msg)

            response = FileResponse(
                file_stream_data,
                content_type=file_format.mime_type,
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential{file_format.file_extension}',
            )

            return cast('HttpResponse', response)

        return self.render_to_response(self.get_context_data(form=form))


class DeviceManualCredentialDownloadView(AbstractDeviceBaseCredentialDownloadView):
    """View to download a password protected domain or application credential in the desired format."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


@method_decorator(login_not_required, name='dispatch')
class DeviceBrowserCredentialDownloadView(
    DownloadTokenRequiredAuthenticationMixin, AbstractDeviceBaseCredentialDownloadView
):
    """View to download a password protected domain or app credential in the desired format from a remote client."""

    is_browser_download = True


class AbstractBrowserOnboardingOTPView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """View to display the OTP for remote credential download (aka. browser onboarding)."""

    http_method_names = ('get',)

    model = IssuedCredentialModel
    template_name = 'devices/credentials/onboarding/browser/otp_view.html'
    redirection_view = 'devices:devices'
    context_object_name = 'credential'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the credential and otp for the browser download process.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        credential = self.get_object()
        device = credential.device
        context = super().get_context_data(**kwargs)

        try:
            cdm = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=credential, device=device)
            cdm.delete()
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            pass

        cdm = RemoteDeviceCredentialDownloadModel(issued_credential_model=credential, device=device)
        cdm.save()

        context.update(
            {
                'device_name': device.common_name,
                'device_id': device.id,
                'credential_id': credential.id,
                'otp': cdm.get_otp_display(),
                'download_url': self.request.build_absolute_uri(reverse('devices:browser_login')),
            }
        )

        context['cred_download_url'] = f'devices:{self.page_name}_credential-download'
        context['browser_cancel'] = f'devices:{self.page_name}_browser_cancel'

        return context


class DeviceBrowserOnboardingOTPView(AbstractBrowserOnboardingOTPView):
    """The browser onboarding OTP view for the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsBrowserOnboardingOTPView(AbstractBrowserOnboardingOTPView):
    """The browser onboarding OTP view for the OPC UA GDS section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractBrowserOnboardingCancelView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """View to cancel the browser onboarding process and delete the associated RemoteDeviceCredentialDownloadModel."""

    http_method_names = ('get',)

    model = IssuedCredentialModel
    context_object_name = 'credential'
    permanent = False

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Cancels the browser onboarding process and deletes the associated RemoteDeviceCredentialDownloadModel.

        Args:
            request: The Django request object.
            *args: Positional arguments are discarded.
            **kwargs: Keyword arguments are discarded.

        Returns:
            The HttpResponseBase object with the desired redirection URL.
        """
        self.object = self.get_object()
        try:
            cdm = RemoteDeviceCredentialDownloadModel.objects.get(
                issued_credential_model=self.object, device=self.object.device
            )
            cdm.delete()
            messages.info(request, 'The browser onboarding process was canceled.')
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            pass

        return HttpResponseRedirect(
            reverse_lazy(f'devices:{self.page_name}_credential-download', kwargs={'pk': self.object.id})
        )


class DeviceBrowserOnboardingCancelView(AbstractBrowserOnboardingCancelView):
    """Cancels the browser onboarding for the devices section."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsBrowserOnboardingCancelView(AbstractBrowserOnboardingCancelView):
    """Cancels the browser onboarding for the OPC UA GDS section."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


@method_decorator(login_not_required, name='dispatch')
class DeviceOnboardingBrowserLoginView(FormView[BrowserLoginForm]):
    """View to handle certificate download requests."""

    http_method_names = ('get', 'post')

    template_name = 'devices/credentials/onboarding/browser/login.html'
    form_class = BrowserLoginForm

    cleaned_data: dict[str, Any]

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        credential_id = cast('int', self.cleaned_data.get('credential_id'))
        credential_download = cast('RemoteDeviceCredentialDownloadModel', self.cleaned_data.get('credential_download'))
        token: str = credential_download.download_token
        return (
            f'{reverse_lazy("devices:browser_domain_credential_download", kwargs={"pk": credential_id})}?token={token}'
        )

    def form_invalid(self, form: BrowserLoginForm) -> HttpResponse:
        """Adds an error message in the case of an invalid OTP.

        Args:
            form: The corresponding form object.

        Returns:
            The Django HttpResponse object.
        """
        messages.error(self.request, _('The provided password is not valid.'))
        return super().form_invalid(form)

    def form_valid(self, form: BrowserLoginForm) -> HttpResponse:
        """Performed if the form was validated successfully and adds the cleaned data to the instance.

        Args:
            form: The corresponding form object.

        Returns:
            The Django HttpResponse object.
        """
        self.cleaned_data = form.cleaned_data
        return super().form_valid(form)


#  ---------------------------------------- Revocation Views ----------------------------------------


class AbstractIssuedCredentialRevocationView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """Revokes a specific issued credential."""

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/confirm_revoke.html'
    context_object_name = 'issued_credential'
    pk_url_kwarg = 'pk'
    form_class = RevokeIssuedCredentialForm

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the primary keys to the context.

        Args:
            kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data.
        """
        context = super().get_context_data(**kwargs)
        context['revoke_form'] = self.form_class()
        context['cert'] = self.object.credential.certificate
        context['cred_revoke_url'] = f'{self.page_category}:{self.page_name}_credential_revoke'
        return context

    def post(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Will try to revoke the requested issued credential.

        Args:
            request: The Django request object.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            Redirect to the devices summary.
        """
        self.object = self.get_object()

        reverse_path = reverse(
            f'{self.page_category}:{self.page_name}_certificate_lifecycle_management',
            kwargs={'pk': self.object.device.pk}
        )

        revoke_form = self.form_class(self.request.POST)
        if revoke_form.is_valid():
            revocation_reason = revoke_form.cleaned_data['revocation_reason']

            status = self.object.credential.certificate.certificate_status
            if status == CertificateModel.CertificateStatus.EXPIRED:
                msg = _('Credential is already expired. Cannot revoke expired certificates.')
                messages.error(self.request, msg)
                return redirect(reverse_path)
            if status == CertificateModel.CertificateStatus.REVOKED:
                msg = _('Certificate is already revoked. Cannot revoke a revoked certificate again.')
                return redirect(reverse_path)
            revoked_successfully, __ = DeviceCredentialRevocation.revoke_certificate(self.object.id, revocation_reason)
            if revoked_successfully:
                msg = _('Successfully revoked one active credential.')
                messages.success(self.request, msg)
            else:
                messages.error(self.request, _('Failed to revoke certificate. See logs for more information.'))

        return redirect(reverse_path)


class DeviceIssuedCredentialRevocationView(AbstractIssuedCredentialRevocationView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsIssuedCredentialRevocationView(AbstractIssuedCredentialRevocationView):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractBulkRevokeView(LoggerMixin, PageContextMixin, ListView[DeviceModel]):
    """View to confirm the deletion of multiple Devices."""

    model = DeviceModel
    template_name = 'devices/confirm_bulk_revoke.html'
    context_object_name = 'devices'

    missing: str = ''
    pks: str = ''
    queryset: QuerySet[DeviceModel]
    form_class = RevokeDevicesForm

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the primary keys to the context.

        Args:
            kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data.
        """
        context = super().get_context_data(**kwargs)
        context['pks'] = self.pks
        context['revoke_form'] = self.form_class(initial={'pks': self.pks})
        context['device_revoke_url'] = f'{self.page_category}:{self.page_name}_device_revoke'
        return context

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Gets the queryset of DeviceModel objects that are requested to be revoked.

        Returns:
            The queryset of DeviceModel objects that are requested to be revoked.
        """
        if not self.pks:
            self.pks = self.kwargs.get('pks', '')
        pks_list = get_primary_keys_from_str_as_list_of_ints(pks=self.pks)
        qs = DeviceModel.objects.filter(pk__in=pks_list)

        found_pks = set(qs.values_list('pk', flat=True))
        missing = set(pks_list) - found_pks

        self.missing = ', '.join(str(pk) for pk in missing)

        return qs

    def _set_queryset(self, request: HttpRequest) -> str | None:
        try:
            self.queryset = self.get_queryset()
        except ValueError:
            err_msg_template = _('Please select the devices you would like to revoke.')
            err_msg = err_msg_template.format(pks=self.pks)
            messages.error(request, err_msg)
            return 'devices:devices'
        except Exception:
            err_msg_template = _('Failed to retrieve the queryset for primary keys: {pks}.See logs for more details.')
            err_msg = err_msg_template.format(pks=self.pks)
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
            return 'devices:devices'

        if self.missing:
            err_msg_template = _('Devices for the following primary keys were not found: {pks}.')
            err_msg = err_msg_template.format(pks=self.missing)
            messages.error(request, err_msg)
            return 'devices:devices'

        return None

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """HTTP GET processing.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            The device deletion view or a redirect to the devices view if one or more pks were not found.
        """
        redirect_name = self._set_queryset(request)
        if redirect_name:
            return redirect(redirect_name)
        messages.warning(
            request, _('This operation will revoke ALL certificates associated with the selected devices.')
        )
        return super().get(request, *args, **kwargs)

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Will try to revoke all certificate assiciated with the requested DeviceModel records.

        Args:
            request: The Django request object.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            Redirect to the devices summary.
        """
        revoke_form = self.form_class(self.request.POST)
        if revoke_form.is_valid():
            self.pks = revoke_form.cleaned_data['pks']
            revocation_reason = revoke_form.cleaned_data['revocation_reason']
            redirect_name = self._set_queryset(request)
            if redirect_name:
                return redirect(redirect_name)

            now = datetime.datetime.now(datetime.UTC)

            issued_credentials_to_revoke_qs = IssuedCredentialModel.objects.filter(
                device__in=self.queryset,
                credential__certificate__revoked_certificate__isnull=True,
                credential__certificate__not_valid_after__gte=now,
            )

            n_revoked = 0
            for credential in issued_credentials_to_revoke_qs:
                revoked_successfully, __ = DeviceCredentialRevocation.revoke_certificate(
                    credential.id, revocation_reason
                )
                if revoked_successfully:
                    n_revoked += 1

            if n_revoked > 0:
                msg = ngettext(
                    'Successfully revoked one active credential.',
                    'Successfully revoked %(count)d active credentials.',
                    n_revoked,
                ) % {'count': n_revoked}

                messages.success(self.request, msg)
            else:
                messages.error(self.request, _('No credentials were revoked.'))

        return redirect('devices:devices')


class DeviceBulkRevokeView(AbstractBulkRevokeView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsBulkRevokeView(AbstractBulkRevokeView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class AbstractBulkDeleteView(LoggerMixin, PageContextMixin, ListView[DeviceModel]):
    """View to confirm the deletion of multiple Devices."""

    model = DeviceModel
    template_name = 'devices/confirm_delete.html'
    context_object_name = 'devices'

    missing: str = ''
    pks: str = ''
    queryset: QuerySet[DeviceModel]
    form_class = DeleteDevicesForm

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the primary keys to the context.

        Args:
            kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data.
        """
        context = super().get_context_data(**kwargs)
        context['pks'] = self.pks
        context['delete_form'] = self.form_class(initial={'pks': self.pks})
        context['device_delete_url'] = f'{self.page_category}:{self.page_name}_device_delete'
        return context

    def get_queryset(self) -> QuerySet[DeviceModel]:
        """Gets the queryset of DeviceModel objects that are requested to be deleted.

        Returns:
            The queryset of DeviceModel objects that are requested to be deleted.
        """
        if not self.pks:
            self.pks = self.kwargs.get('pks', '')
        pks_list = get_primary_keys_from_str_as_list_of_ints(pks=self.pks)
        qs = DeviceModel.objects.filter(pk__in=pks_list)

        found_pks = set(qs.values_list('pk', flat=True))
        missing = set(pks_list) - found_pks

        self.missing = ', '.join(str(pk) for pk in missing)

        return qs

    def _set_queryset(self, request: HttpRequest) -> str | None:
        try:
            self.queryset = self.get_queryset()
        except ValueError:
            err_msg_template = _('Please select the devices you would like to delete.')
            err_msg = err_msg_template.format(pks=self.pks)
            messages.error(request, err_msg)
            return 'devices:devices'
        except Exception:
            err_msg_template = _('Failed to retrieve the queryset for primary keys: {pks}.See logs for more details.')
            err_msg = err_msg_template.format(pks=self.pks)
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
            return 'devices:devices'

        if self.missing:
            err_msg_template = _('Devices for the following primary keys were not found: {pks}.')
            err_msg = err_msg_template.format(pks=self.missing)
            messages.error(request, err_msg)
            return 'devices:devices'

        return None

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """HTTP GET processing.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            The device deletion view or a redirect to the devices view if one or more pks were not found.
        """
        redirect_name = self._set_queryset(request)
        if redirect_name:
            return redirect(redirect_name)
        messages.warning(
            request, _('This operation will revoke ALL certificates associated with the selected devices.')
        )
        return super().get(request, *args, **kwargs)

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """HTTP POST processing which will try to delete all requested DeviceModel records.

        Args:
            request: The Django request object.
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

        Returns:
            Redirect to the devices summary.
        """
        delete_form = self.form_class(self.request.POST)
        if delete_form.is_valid():
            self.pks = delete_form.cleaned_data['pks']
            redirect_name = self._set_queryset(request)
            if redirect_name:
                return redirect(redirect_name)

        try:
            count, __ = self.queryset.delete()
            success_msg_template = _(
                'Successfully deleted {count} devices. All corresponding certificates have been revoked.'
            )
            success_msg = success_msg_template.format(count=count)
            messages.success(request, success_msg)
        except Exception:
            err_msg = 'Failed to delete DeviceModel records.'
            self.logger.exception(err_msg)
            messages.error(request, _('Failed to delete DeviceModel records. See logs for more information.'))

        return redirect('devices:devices')


class DeviceBulkDeleteView(AbstractBulkDeleteView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsBulkDeleteView(AbstractBulkDeleteView):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
