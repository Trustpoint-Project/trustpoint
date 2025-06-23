"""This module contains all views concerning the devices application."""

from __future__ import annotations

import abc
import datetime
import io
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.forms import BaseModelForm
from django.http import FileResponse, Http404, HttpResponse, HttpResponseBase
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext
from django.views.generic.base import RedirectView, View
from django.views.generic.detail import DetailView, SingleObjectMixin
from django.views.generic.edit import CreateView, FormView
from django.views.generic.list import ListView
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel
from trustpoint_core.archiver import Archiver
from trustpoint_core.serializer import CredentialFileFormat
from util.mult_obj_views import get_primary_keys_from_str_as_list_of_ints

from devices.forms import (
    BrowserLoginForm,
    CreateDeviceForm,
    CreateOpcUaGdsForm,
    CredentialDownloadForm,
    DeleteDevicesForm,
    IssueOpcUaClientCredentialForm,
    IssueOpcUaServerCredentialForm,
    IssueTlsClientCredentialForm,
    IssueTlsServerCredentialForm,
    RevokeDevicesForm,
    RevokeIssuedCredentialForm,
)
from devices.issuer import (
    LocalTlsClientCredentialIssuer,
    LocalTlsServerCredentialIssuer,
    OpcUaClientCredentialIssuer,
    OpcUaServerCredentialIssuer,
)
from devices.models import DeviceModel, IssuedCredentialModel, RemoteDeviceCredentialDownloadModel
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

    _ViewType = View

else:
    _ViewType = object

CredentialFormClass = TypeVar('CredentialFormClass', bound='BaseCredentialForm')
TlsCredentialIssuerClass = TypeVar('TlsCredentialIssuerClass', bound='BaseTlsCredentialIssuer')

DeviceWithoutDomainErrorMsg = _('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = _('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = _('No active trustpoint TLS server credential found.')

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg


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
        return context

    def get_ordering(self) -> str | Sequence[str] | None:
        """Returns the sort parameters as a list.

        Returns:
           The sort parameters, if any. Otherwise the default sort parameter.
        """
        return self.request.GET.getlist('sort', [self.default_sort_param])

    @staticmethod
    def _get_clm_button_html(record: DeviceModel) -> SafeString:
        """Gets the HTML for the CLM button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            The HTML of the hyperlink for the CLM button.
        """
        clm_url = reverse('devices:certificate_lifecycle_management', kwargs={'pk': record.pk})

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
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/details.html'
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY

class DeviceDetailsView(AbstractDeviceDetailsView):
    """Details view for common devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaDeviceDetailsView(AbstractDeviceDetailsView):
    """Details view for OPC UA devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


# ------------------------------------------------- Device Create View -------------------------------------------------


class AbstractCreateDeviceView[T: BaseModelForm[DeviceModel]](PageContextMixin, CreateView[DeviceModel, T]):
    """Abstract Device Create View."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    form_class: type[T]
    template_name = 'devices/add.html'

    page_category = DEVICES_PAGE_CATEGORY

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        if self.object is None:
            err_msg = _('Unexpected error occurred. The object was likely not created and saved.')
            raise Http404(err_msg)
        if self.object.domain_credential_onboarding:
            return str(reverse_lazy('devices:help_dispatch_domain', kwargs={'pk': self.object.id}))

        return str(reverse_lazy('devices:help_dispatch_device_type_redirect', kwargs={'pk': self.object.id}))


class CreateDeviceView(AbstractCreateDeviceView[CreateDeviceForm]):
    """Device Create View."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    form_class = CreateDeviceForm


class CreateOpcUaGdsView(AbstractCreateDeviceView[CreateOpcUaGdsForm]):
    """OPC UA GDS Create View."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

    form_class = CreateOpcUaGdsForm

    def form_valid(self, form: CreateOpcUaGdsForm) -> HttpResponse:
        """Set opc_ua_gds to True before saving the device.

        Args:
            form: The CreateOocUaGdsForm to create a OPC UA GDS.

        Returns:
            The HttpResponse from super().form_valid(form).
        """
        device = form.save(commit=False)
        device.device_type = DeviceModel.DeviceType.OPC_UA_GDS
        device.save()
        return super().form_valid(form)


# ------------------------------------------ Certificate Lifecycle Management ------------------------------------------


class DeviceCertificateLifecycleManagementSummaryView(PageContextMixin, DetailView[DeviceModel]):
    """This is the CLM summary view in the devices section."""

    http_method_names = ('get',)

    model = DeviceModel
    template_name = 'devices/credentials/certificate_lifecycle_management.html'
    context_object_name = 'device'

    default_sort_param = 'common_name'
    issued_creds_qs: QuerySet[IssuedCredentialModel]
    domain_credentials_qs: QuerySet[IssuedCredentialModel]
    application_credentials_qs: QuerySet[IssuedCredentialModel]

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

        paginator_application = Paginator(self.application_credentials_qs, UIConfig.paginate_by)
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

        return context

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

    @staticmethod
    def _get_revoke_button_html(record: IssuedCredentialModel) -> str:
        """Gets the HTML for the revoke button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            the HTML of the hyperlink for the revoke button.
        """
        if record.credential.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED:
            return format_html('<a class="btn btn-danger tp-table-btn w-100 disabled">{}</a>', _('Revoked'))
        url = reverse('devices:credential_revocation', kwargs={'pk': record.pk})
        return format_html('<a href="{}" class="btn btn-danger tp-table-btn w-100">{}</a>', url, _('Revoke'))


#  ------------------------------ Certificate Lifecycle Management - Credential Issuance -------------------------------


class DeviceIssueCredentialView(
    PageContextMixin,
    SingleObjectMixin[DeviceModel],
    FormView[CredentialFormClass],
    Generic[CredentialFormClass, TlsCredentialIssuerClass],
):
    """Base view to issue device credentials."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'
    form_class: type[CredentialFormClass]
    issuer_class: type[TlsCredentialIssuerClass]
    friendly_name: str

    def get_initial(self) -> dict[str, Any]:
        """Gets the initial data for the corresponding form.

        Returns:
            The initial data for the corresponding form.
        """
        initial = super().get_initial()
        if self.issuer_class:
            if self.object.domain is None:
                raise Http404(DeviceWithoutDomainErrorMsg)
            initial.update(self.issuer_class.get_fixed_values(device=self.object, domain=self.object.domain))
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        """This method ads the concerning device model to the form kwargs and returns them.

        Returns:
            The form kwargs including the concerning device model.
        """
        form_kwargs = super().get_form_kwargs()
        form_kwargs.update({'device': self.object})
        return form_kwargs

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        return cast(
            'str', reverse_lazy('devices:certificate_lifecycle_management', kwargs={'pk': self.get_object().id})
        )

    def form_valid(self, form: CredentialFormClass) -> HttpResponse:
        """This method is executed if the form submit data was valid.

        Args:
            form: The form that was used to validate the data.

        Returns:
            The HTTP Response object after successful validation of the form data.
        """
        credential = self.issue_credential(device=self.object, cleaned_data=form.cleaned_data)
        messages.success(
            self.request, f'Successfully issued {self.friendly_name} for device {credential.device.common_name}'
        )
        return super().form_valid(form)

    @abc.abstractmethod
    def issue_credential(self, device: DeviceModel, cleaned_data: dict[str, Any]) -> IssuedCredentialModel:
        """Abstract method to issue a credential.

        Args:
            device: The device to be associated with the new credential.
            cleaned_data: The validated form data.

        Returns:
            The IssuedCredentialModel object that was created and saved.
        """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Adds the object model to the instance and forwards to super().post().

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().post().
            **kwargs: Keyword arguments passed to super().post().

        Returns:
            The HttpResponseBase object returned by super().post().
        """
        self.object = self.get_object()
        return super().post(request, *args, **kwargs)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Adds the object model to the instance and forwards to super().get().

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            The HttpResponseBase object returned by super().get().
        """
        self.object = self.get_object()
        return super().get(request, *args, **kwargs)


class DeviceIssueTlsClientCredential(
    DeviceIssueCredentialView[IssueTlsClientCredentialForm, LocalTlsClientCredentialIssuer]
):
    """View to issue a new TLS client credential."""

    form_class = IssueTlsClientCredentialForm
    issuer_class = LocalTlsClientCredentialIssuer
    friendly_name = 'TLS client credential'

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


class DeviceIssueTlsServerCredential(
    DeviceIssueCredentialView[IssueTlsServerCredentialForm, LocalTlsServerCredentialIssuer]
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


class DeviceIssueOpcUaClientCredential(
    DeviceIssueCredentialView[IssueOpcUaClientCredentialForm, OpcUaClientCredentialIssuer]
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


class DeviceIssueOpcUaServerCredential(
    DeviceIssueCredentialView[IssueOpcUaServerCredentialForm, OpcUaServerCredentialIssuer]
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


#  ----------------------------------- Certificate Lifecycle Management - Downloads ------------------------------------


class DownloadPageDispatcherView(PageContextMixin, SingleObjectMixin[IssuedCredentialModel], RedirectView):
    """Redirects depending on the type of credential, that is if a private key is available or not."""

    http_method_names = ('get',)

    model: type[IssuedCredentialModel] = IssuedCredentialModel
    permanent = False

    def get_redirect_url(self, *args: Any, **kwargs: Any) -> str:
        """Gets the redirection URL depending on the type credential, that is if a private key is available or not.

        Args:
            *args: Positional arguments are discarded.
            **kwargs: Keyword arguments are discarded.

        Returns:
            The redirect URL.
        """
        del args
        del kwargs

        issued_credential: IssuedCredentialModel = self.get_object()
        if issued_credential.credential.private_key:
            return f'{reverse("devices:credential-download", kwargs={"pk": issued_credential.id})}'
        return f'{reverse("devices:certificate-download", kwargs={"pk": issued_credential.id})}'


class CertificateDownloadView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """View for downloading certificates."""

    http_method_names = ('get',)

    model: type[IssuedCredentialModel] = IssuedCredentialModel
    template_name = 'devices/credentials/certificate_download.html'
    context_object_name = 'issued_credential'


class DeviceBaseCredentialDownloadView(
    PageContextMixin, DetailView[IssuedCredentialModel], FormView[CredentialDownloadForm]
):
    """View to download a password protected application credential in the desired format.

    Inherited by the domain and application credential download views. It is not intended for direct use.
    """

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/credentials/credential_download.html'
    form_class = CredentialDownloadForm
    context_object_name = 'credential'
    is_browser_download = False

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
            err_msg = 'Credential is not an issued credential'
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
        return context

    # TODO(AlexHx8472): This needs to return a success url redirect and then download the file. # noqa: FIX002
    # TODO(AlexHx8472): The FileResponse must then be returned from a get or post method.       # noqa: FIX002
    def form_valid(self, form: CredentialDownloadForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to start the download process of the desired file.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        issued_credential_model = self.get_object()
        password = form.cleaned_data['password'].encode()

        try:
            file_format = CredentialFileFormat(self.request.POST.get('file_format'))
        except ValueError as exception:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg) from exception

        credential_model = issued_credential_model.credential
        credential_serializer = credential_model.get_credential_serializer()

        private_key_serializer = credential_serializer.get_private_key_serializer()
        certificate_serializer = credential_serializer.get_certificate_serializer()
        cert_collection_serializer = credential_serializer.get_additional_certificates_serializer()
        if not private_key_serializer or not certificate_serializer or not cert_collection_serializer:
            raise Http404

        credential_purpose = IssuedCredentialModel.IssuedCredentialPurpose(
            issued_credential_model.issued_credential_purpose
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


class DeviceManualCredentialDownloadView(DeviceBaseCredentialDownloadView):
    """View to download a password protected domain or application credential in the desired format."""


class DeviceBrowserOnboardingOTPView(PageContextMixin, DetailView[IssuedCredentialModel]):
    """View to display the OTP for remote credential download (aka. browser onboarding)."""

    http_method_names = ('get',)

    model = IssuedCredentialModel
    template_name = 'devices/credentials/onboarding/browser/otp_view.html'
    redirection_view = 'devices:devices'
    context_object_name = 'credential'

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
        return context


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


class DownloadTokenRequiredAuthenticationMixin(_ViewType):
    """Mixin which checks the token included in the URL for browser download views."""

    http_method_names = ('get', 'post')
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

        return super().dispatch(request, *args, **kwargs)


@method_decorator(login_not_required, name='dispatch')
class DeviceBrowserCredentialDownloadView(DownloadTokenRequiredAuthenticationMixin, DeviceBaseCredentialDownloadView):
    """View to download a password protected domain or app credential in the desired format from a remote client."""

    is_browser_download = True


class DeviceBrowserOnboardingCancelView(PageContextMixin, SingleObjectMixin[IssuedCredentialModel], RedirectView):
    """View to cancel the browser onboarding process and delete the associated RemoteDeviceCredentialDownloadModel."""

    http_method_names = ('get',)

    model = IssuedCredentialModel
    context_object_name = 'credential'
    permanent = False

    def get_redirect_url(self, *args: Any, **kwargs: Any) -> str:
        """Gets the redirection URL.

        Args:
            *args: Positional arguments are discarded.
            **kwargs: Keyword arguments are discarded.

        Returns:
            The redirect URL.
        """
        del args
        del kwargs

        return str(reverse_lazy('devices:credential-download', kwargs={'pk': self.object.id}))

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Cancels the browser onboarding process and deletes the associated RemoteDeviceCredentialDownloadModel.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

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

        return super().get(request, *args, **kwargs)


#  ---------------------------------------- Revocation Views ----------------------------------------


class IssuedCredentialRevocationView(LoggerMixin, PageContextMixin, DetailView[IssuedCredentialModel]):
    """Revokes a specific issued credential."""

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/confirm_revoke.html'
    context_object_name = 'issued_credential'
    pk_url_kwarg = 'pk'
    form_class = RevokeIssuedCredentialForm

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
        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """HTTP GET processing.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            The issued credential revocation view or a redirect to the devices view if one or more pks were not found.
        """
        try:
            self.object = self.get_object()
        except Exception:
            err_msg = f'Failed to get issued credential with pk: {self.pk_url_kwarg}.'
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
            return redirect('devices:devices')

        return super().get(request, *args, **kwargs)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Will try to revoke the requested issued credential.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            Redirect to the devices summary.
        """
        del args, kwargs

        try:
            self.object = self.get_object()
        except Exception:
            err_msg = f'Failed to get issued credential with pk: {self.pk_url_kwarg}.'
            self.logger.exception(err_msg)
            messages.error(request, err_msg)
            return redirect('devices:devices')

        revoke_form = self.form_class(self.request.POST)
        if revoke_form.is_valid():
            revocation_reason = revoke_form.cleaned_data['revocation_reason']

            status = self.object.credential.certificate.certificate_status
            if status == CertificateModel.CertificateStatus.EXPIRED:
                msg = _('Credential is already expired. Cannot revoke expired certificates.')
                messages.error(self.request, msg)
                return redirect('devices:devices')
            if status == CertificateModel.CertificateStatus.REVOKED:
                msg = _('Certificate is already revoked. Cannot revoke a revoked certificate again.')
                return redirect('devices:devices')
            revoked_successfully, __ = DeviceCredentialRevocation.revoke_certificate(self.object.id, revocation_reason)
            if revoked_successfully:
                msg = _('Successfully revoked one active credential.')
                messages.success(self.request, msg)
            else:
                messages.error(self.request, _('Failed to revoke certificate. See logs for more information.'))

        return redirect('devices:devices')


class DeviceBulkRevokeView(LoggerMixin, PageContextMixin, ListView[DeviceModel]):
    """View to confirm the deletion of multiple Devices."""

    model = DeviceModel
    template_name = 'devices/confirm_bulk_evoke.html'
    context_object_name = 'devices'

    missing: str = ''
    pks: str = ''
    queryset: QuerySet[DeviceModel]
    form_class = RevokeDevicesForm

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

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Will try to revoke all certificate assiciated with the requested DeviceModel records.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            Redirect to the devices summary.
        """
        del args, kwargs

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


class DeviceBulkDeleteView(LoggerMixin, PageContextMixin, ListView[DeviceModel]):
    """View to confirm the deletion of multiple Devices."""

    model = DeviceModel
    template_name = 'devices/confirm_delete.html'
    context_object_name = 'devices'

    missing: str = ''
    pks: str = ''
    queryset: QuerySet[DeviceModel]
    form_class = DeleteDevicesForm

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

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """HTTP POST processing which will try to delete all requested DeviceModel records.

        Args:
            request: The Django request object.
            *args: Positional arguments passed to super().get().
            **kwargs: Keyword arguments passed to super().get().

        Returns:
            Redirect to the devices summary.
        """
        del args, kwargs

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
