"""This module contains all views concerning the devices application."""

from __future__ import annotations

import datetime
import io
from abc import abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar, cast

from cryptography.hazmat.primitives import serialization
from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.forms import BaseModelForm
from django.http import FileResponse, Http404, HttpResponse, HttpResponseBase
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext
from django.views.generic.base import RedirectView, View
from django.views.generic.detail import DetailView, SingleObjectMixin
from django.views.generic.edit import CreateView, FormMixin, FormView
from django.views.generic.list import ListView
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel
from pki.models.devid_registration import DevIdRegistration
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from trustpoint_core import oid  # type: ignore[import-untyped]
from trustpoint_core.file_builder.enum import ArchiveFormat  # type: ignore[import-untyped]
from trustpoint_core.serializer import CredentialSerializer  # type: ignore[import-untyped]

from devices.forms import (
    BrowserLoginForm,
    CreateDeviceForm,
    CredentialDownloadForm,
    CredentialRevocationForm,
    IssueOpcUaClientCredentialForm,
    IssueOpcUaServerCredentialForm,
    IssueTlsClientCredentialForm,
    IssueTlsServerCredentialForm, CreateOpcUaGdsForm,
)
from devices.issuer import (
    LocalTlsClientCredentialIssuer,
    LocalTlsServerCredentialIssuer,
    OpcUaClientCredentialIssuer,
    OpcUaServerCredentialIssuer,
)
from devices.models import DeviceModel, IssuedCredentialModel, RemoteDeviceCredentialDownloadModel
from devices.revocation import DeviceCredentialRevocation
from trustpoint.settings import UIConfig
from trustpoint.views.base import ListInDetailView, SortableTableMixin

if TYPE_CHECKING:
    import ipaddress
    from typing import Any, ClassVar

    from django.http.request import HttpRequest
    from django.utils.safestring import SafeString

    # noinspection PyUnresolvedReferences
    from devices.forms import BaseCredentialForm

    # noinspection PyUnresolvedReferences
    from devices.issuer import BaseTlsCredentialIssuer

    _DispatchableType = View

else:
    _DispatchableType = object

CredentialFormClass = TypeVar('CredentialFormClass', bound='BaseCredentialForm')
TlsCredentialIssuerClass = TypeVar('TlsCredentialIssuerClass', bound='BaseTlsCredentialIssuer')

# TODO(AlexHx8472): Derived CBVs must only derive from one Django view which must be the last one.  # noqa: FIX002


# --------------------------------------------------- Device Mixins ----------------------------------------------------


class DeviceContextMixin:
    """Mixin which adds data to the context for the devices application."""

    extra_context: ClassVar = {'page_category': 'devices', 'page_name': 'devices'}


# ----------------------------------------------------- Main Pages -----------------------------------------------------


class DeviceTableView(DeviceContextMixin, SortableTableMixin, ListView[DeviceModel]):
    """Device Table View."""

    http_method_names = ('get',)

    model = DeviceModel
    template_name = 'devices/devices.html'
    context_object_name = 'devices'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'

    def get_queryset(self):
        """Filter queryset to only include devices where opc_ua_gds is False."""
        return super().get_queryset().filter(opc_ua_gds=False)

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
            device.revoke_button = self._get_revoke_button_html(device)

        return context

    @staticmethod
    def _get_clm_button_html(record: DeviceModel) -> SafeString:
        """Gets the HTML for the CLM button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            The HTML of the hyperlink for the CLM button.
        """
        # noinspection PyDeprecation
        return format_html(
            '<a href="certificate-lifecycle-management/{}/" class="btn btn-primary tp-table-btn w-100">Manage</a>',
            record.pk,
        )

    @staticmethod
    def _get_revoke_button_html(record: DeviceModel) -> SafeString:
        """Gets the HTML for the revoke button in the devices table.

        Args:
            record: The corresponding DeviceModel.

        Returns:
            the HTML of the hyperlink for the revoke button.
        """
        qs = IssuedCredentialModel.objects.filter(device=record)
        for credential in qs:
            if credential.credential.certificate.certificate_status == CertificateModel.CertificateStatus.OK:
                # noinspection PyDeprecation
                return format_html(
                    '<a href="revoke/{}/" class="btn btn-danger tp-table-btn w-100">{}</a>', record.pk, _('Revoke')
                )
        # noinspection PyDeprecation
        return format_html('<a class="btn btn-danger tp-table-btn w-100 disabled">{}</a>', _('Revoke'))

class OpcUaGdsTableView(DeviceTableView):
    """Table View for devices where opc_ua_gds is True."""

    template_name = 'devices/opc_ua_gds.html'
    extra_context: ClassVar = {'page_category': 'devices', 'page_name': 'opc_ua_gds'}

    def get_queryset(self):
        """Filter queryset to only include devices where opc_ua_gds is True."""
        devices = super().get_queryset().filter(opc_ua_gds=True)
        return devices


class CreateDeviceView(DeviceContextMixin, CreateView[DeviceModel, BaseModelForm[DeviceModel]]):
    """Device Create View."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    form_class = CreateDeviceForm
    template_name = 'devices/add.html'

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        if self.object is None:
            err_msg = 'Unexpected error occurred. The object was likely not created and saved.'
            raise Http404(err_msg)
        if self.object.domain_credential_onboarding:
            return str(reverse_lazy('devices:help_dispatch_domain', kwargs={'pk': self.object.id}))

        return str(reverse_lazy('devices:help_dispatch_application', kwargs={'pk': self.object.id}))

class CreateOpcUaGdsView(CreateDeviceView):
    """OPC UA GDS Create View."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    form_class = CreateOpcUaGdsForm
    template_name = 'devices/add.html'

    def form_valid(self, form):
        """Set opc_ua_gds to True before saving the device."""
        device = form.save(commit=False)
        device.opc_ua_gds = True
        device.save()
        return super().form_valid(form)

class DeviceDetailsView(DeviceContextMixin, DetailView[DeviceModel]):
    """Device Details View."""

    http_method_names = ('get',)

    model = DeviceModel
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/details.html'
    context_object_name = 'device'


# ------------------------------------------ Certificate Lifecycle Management ------------------------------------------


class DeviceCertificateLifecycleManagementSummaryView(DeviceContextMixin, SortableTableMixin, ListInDetailView):
    """This is the CLM summary view in the devices section."""

    http_method_names = ('get',)

    detail_model = DeviceModel
    template_name = 'devices/credentials/certificate_lifecycle_management.html'
    detail_context_object_name = 'device'
    model = IssuedCredentialModel
    context_object_name = 'issued_credentials'
    default_sort_param = 'common_name'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the paginator and credential details to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the clm summary page.
        """
        context = super().get_context_data(**kwargs)

        device = self.get_object()
        qs = super().get_queryset()  # inherited from SortableTableMixin, sorted query

        domain_credentials = qs.filter(
            Q(device=device)
            & Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value)
        )

        application_credentials = qs.filter(
            Q(device=device)
            & Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value)
        )

        context['domain_credentials'] = domain_credentials
        context['application_credentials'] = application_credentials

        paginator_domain = Paginator(domain_credentials, UIConfig.paginate_by)
        page_number_domain = self.request.GET.get('page', 1)
        context['domain_credentials'] = paginator_domain.get_page(page_number_domain)
        context['is_paginated'] = paginator_domain.num_pages > 1

        paginator_application = Paginator(application_credentials, UIConfig.paginate_by)
        page_number_application = self.request.GET.get('page-a', 1)
        context['application_credentials'] = paginator_application.get_page(page_number_application)
        context['is_paginated_a'] = paginator_application.num_pages > 1

        for cred in context['domain_credentials']:
            cred.expires_in = self._get_expires_in(cred)
            cred.expiration_date = cast(datetime.datetime, cred.credential.certificate.not_valid_after)
            cred.revoke = self._get_revoke_button_html(cred)

        for cred in context['application_credentials']:
            cred.expires_in = self._get_expires_in(cred)
            cred.expiration_date = cast(datetime.datetime, cred.credential.certificate.not_valid_after)
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
            # noinspection PyDeprecation
            return format_html('<a class="btn btn-danger tp-table-btn w-100 disabled">{}</a>', _('Revoked'))
        # noinspection PyDeprecation
        return format_html(
            '<a href="revoke/{}/" class="btn btn-danger tp-table-btn w-100">{}</a>', record.pk, _('Revoke')
        )


#  ------------------------------ Certificate Lifecycle Management - Credential Issuance -------------------------------


class DeviceIssueCredentialView(
    DeviceContextMixin,
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
    object: DeviceModel

    def get_initial(self) -> dict[str, Any]:
        """Gets the initial data for the corresponding form.

        Returns:
            The initial data for the corresponding form.
        """
        initial = super().get_initial()
        if self.issuer_class:
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
        return cast(str, reverse_lazy('devices:certificate_lifecycle_management', kwargs={'pk': self.get_object().id}))

    def form_valid(self, form: CredentialFormClass) -> HttpResponse:
        """This method is executed if the form submit data was valid.

        Args:
            form: The form that was used to validate the data.

        Returns:
            The HTTP Response object after successful validation of the form data.
        """
        credential = self.issue_credential(device=self.object, cleaned_data=form.cleaned_data)
        messages.success(
            self.request, f'Successfully issued {self.friendly_name} for device {credential.device.unique_name}'
        )
        return super().form_valid(form)

    @abstractmethod
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
        common_name = cast(str, cleaned_data.get('common_name'))
        validity = cast(int, cleaned_data.get('validity'))
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
        common_name = cast(str, cleaned_data.get('common_name'))
        if not common_name:
            raise Http404
        issuer = self.issuer_class(device=device, domain=device.domain)
        return issuer.issue_tls_server_credential(
            common_name=common_name,
            ipv4_addresses=cast('list[ipaddress.IPv4Address]', cleaned_data.get('ipv4_addresses')),
            ipv6_addresses=cast('list[ipaddress.IPv6Address]', cleaned_data.get('ipv6_addresses')),
            domain_names=cast(list[str], cleaned_data.get('domain_names')),
            san_critical=False,
            validity_days=cast(int, cleaned_data.get('validity')),
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
        issuer = self.issuer_class(device=device, domain=device.domain)
        return issuer.issue_opcua_client_credential(
            common_name=cast(str, cleaned_data.get('common_name')),
            application_uri=cast(str, cleaned_data.get('application_uri')),
            validity_days=cast(int, cleaned_data.get('validity')),
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
        common_name = cast(str, cleaned_data.get('common_name'))
        if not common_name:
            raise Http404
        issuer = self.issuer_class(device=device, domain=device.domain)

        ipv4_addresses: list[ipaddress.IPv4Address] = cleaned_data.get('ipv4_addresses', [])
        ipv6_addresses: list[ipaddress.IPv6Address] = cleaned_data.get('ipv6_addresses', [])
        domain_names: list[str] = cleaned_data.get('domain_names', [])
        validity_days: int = cleaned_data.get('validity', 0)

        return issuer.issue_opcua_server_credential(
            common_name=common_name,
            application_uri=cast(str, cleaned_data.get('application_uri')),
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            domain_names=domain_names,
            validity_days=validity_days,
        )


#  ----------------------------------- Certificate Lifecycle Management - Help Pages -----------------------------------

class HelpDispatchDomainCredentialView(DeviceContextMixin, SingleObjectMixin[DeviceModel], RedirectView):
    """Redirects to the required help pages depending on the onboarding protocol.

    If no help page could be determined, it will redirect to the devices page.
    """

    http_method_names = ('get',)

    model: type[DeviceModel] = DeviceModel
    permanent = False

    def get_redirect_url(self, *args: Any, **kwargs: Any) -> str:
        """Gets the redirection URL (Domain Credentials) for the required help page.

        Args:
            *args: Positional arguments are discarded.
            **kwargs: Keyword arguments are discarded.

        Returns:
            The redirection URL.
        """
        del args
        del kwargs

        device: DeviceModel = self.get_object()

        if (
            not device.domain_credential_onboarding
            and device.pki_protocol == device.PkiProtocol.EST_PASSWORD.value
        ):
            return f'{reverse("devices:help-no-onboarding_est-username-password", kwargs={"pk": device.id})}'

        if device.onboarding_protocol == device.OnboardingProtocol.CMP_SHARED_SECRET.value:
            return f'{reverse("devices:help-onboarding_cmp-shared-secret", kwargs={"pk": device.id})}'

        if device.onboarding_protocol == device.OnboardingProtocol.CMP_IDEVID.value:
            return f'{reverse("devices:help-onboarding_cmp-idevid", kwargs={"pk": device.id})}'

        if device.onboarding_protocol == device.OnboardingProtocol.EST_PASSWORD.value:
            return f'{reverse("devices:help-onboarding_est-username-password", kwargs={"pk": device.id})}'

        return f'{reverse("devices:devices")}'

class HelpDispatchApplicationCredentialView(DeviceContextMixin, SingleObjectMixin[DeviceModel], RedirectView):
    """Redirects to the required help pages depending on PKI protocol.

    If no help page could be determined, it will redirect to the devices page.
    """

    http_method_names = ('get',)

    model: type[DeviceModel] = DeviceModel
    permanent = False

    def get_redirect_url(self, *args: Any, **kwargs: Any) -> str:
        """Gets the redirection URL (Application Credentials) for the required help page.

        Args:
            *args: Positional arguments are discarded.
            **kwargs: Keyword arguments are discarded.

        Returns:
            The redirection URL.
        """
        del args
        del kwargs

        device: DeviceModel = self.get_object()

        if (
                not device.domain_credential_onboarding
                and device.pki_protocol == device.PkiProtocol.CMP_SHARED_SECRET.value
        ):
            return f'{reverse("devices:help_no-onboarding_cmp-shared-secret", kwargs={"pk": device.id})}'

        if device.onboarding_protocol in {
            device.OnboardingProtocol.CMP_SHARED_SECRET.value,
            device.OnboardingProtocol.CMP_IDEVID.value
        }:
            return f'{reverse("devices:help-onboarding_cmp-application-credentials", kwargs={"pk": device.id})}'

        if (
                not device.domain_credential_onboarding
                and device.pki_protocol == device.PkiProtocol.EST_PASSWORD.value
        ):
            return f'{reverse("devices:help-no-onboarding_est-username-password", kwargs={"pk": device.id})}'

        if device.onboarding_protocol in {
            device.OnboardingProtocol.EST_PASSWORD.value,
        }:
            return f'{reverse("devices:help-onboarding_est-application-credentials", kwargs={"pk": device.id})}'

        return f"{reverse('devices:devices')}"


class HelpDomainCredentialCmpContextView(DeviceContextMixin, DetailView[DeviceModel]):
    """Base view for CMP help views concerning the domain credential, not intended to be used directly."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        device: DeviceModel = self.object
        context['host'] = (f'{self.request.META.get("REMOTE_ADDR", "127.0.0.1")}:'
                           f'{self.request.META.get("SERVER_PORT", "443")}')
        context.update(self._get_domain_credential_cmp_context(device=device))
        return context

    @staticmethod
    def _get_domain_credential_cmp_context(device: DeviceModel) -> dict[str, Any]:
        """Provides the context for cmp commands using client based authentication.

        Args:
            device: The corresponding device model.

        Returns:
            The required context.
        """
        context = {}
        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = (
                f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'
            )
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            domain_credential_key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem'
            )
            key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )
        else:
            err_msg = _('Unsupported public key algorithm')
            raise ValueError(err_msg)

        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = (
            device.domain.issuing_ca.credential.get_certificate()
            .public_bytes(encoding=serialization.Encoding.PEM)
            .decode()
        )
        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'

        return context

class HelpDomainCredentialEstContextView(DeviceContextMixin, DetailView[DeviceModel]):
    """Base view for CMP help views concerning the domain credential, not intended to be used directly."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        device: DeviceModel = self.object
        context['host'] = (f'{self.request.META.get("REMOTE_ADDR", "127.0.0.1")}:'
                           f'{self.request.META.get("SERVER_PORT", "443")}')

        context.update(self._get_domain_credential_est_context(device=device))
        return context

    @staticmethod
    def _get_domain_credential_est_context(device: DeviceModel) -> dict[str, Any]:
        """Provides the context for est commands using client based authentication.

        Args:
            device: The corresponding device model.

        Returns:
            The required context.
        """
        context = {}
        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = (
                f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'
            )
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            domain_credential_key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem'
            )
            key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )
        else:
            err_msg = _('Unsupported public key algorithm')
            raise ValueError(err_msg)

        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if tls_cert:
            context['trustpoint_server_certificate'] = (
                tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8'))

        domain = device.domain
        context.update({
            'allow_app_certs_without_domain': domain.allow_app_certs_without_domain,
            'allow_username_password_registration': domain.allow_username_password_registration,
            'username_password_auth': domain.username_password_auth,
            'domain_credential_auth': domain.domain_credential_auth,
        })

        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'
        context['domain_credential_cn'] = f'Trustpoint Domain Credential'

        return context

class NoOnboardingEstUsernamePasswordHelpView(HelpDomainCredentialEstContextView):
    """View to provide help information for EST username/password authentication with no onboarding."""

    template_name = 'devices/help/no_onboarding/est_username_password.html'


class OnboardingEstUsernamePasswordHelpView(HelpDomainCredentialEstContextView):
    """View to provide help information for EST username/password authentication for onboarding."""

    template_name = 'devices/help/onboarding/est_username_password.html'


class OnboardingEstApplicationCredentialsHelpView(HelpDomainCredentialEstContextView):
    """View to provide help information for EST domain credential authentication."""

    template_name = 'devices/help/onboarding/est_application_credentials.html'

class NoOnboardingCmpSharedSecretHelpView(DeviceContextMixin, DetailView[DeviceModel]):
    """Help view for the case of no onboarding using CMP shared-secret."""

    http_method_names = ('get',)

    model = DeviceModel
    template_name = 'devices/help/no_onboarding/cmp_shared_secret.html'
    context_object_name = 'device'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        device: DeviceModel = self.object

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )
        else:
            err_msg = _('Unsupported public key algorithm')
            raise ValueError(err_msg)

        context['host'] = (f'{self.request.META.get("REMOTE_ADDR", "127.0.0.1")}:'
                           f'{self.request.META.get("SERVER_PORT", "443")}')
        context['key_gen_command'] = key_gen_command
        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'
        return context


class OnboardingCmpSharedSecretHelpView(HelpDomainCredentialCmpContextView):
    """Help view for the onboarding cmp-shared secret case."""

    template_name = 'devices/help/onboarding/cmp_shared_secret.html'


class OnboardingCmpIdevidHelpView(HelpDomainCredentialCmpContextView):
    """Help view for the onboarding IDeviD case."""

    template_name = 'devices/help/onboarding/cmp_idevid.html'

class OnboardingCmpApplicationCredentialsHelpView(HelpDomainCredentialCmpContextView):
    """Help view for enrolling application credentials via CMP."""

    template_name = 'devices/help/onboarding/cmp_application_credentials.html'

class OnboardingIdevidRegistrationHelpView(DeviceContextMixin, DetailView[DevIdRegistration]):
    """Help view for the IDevID Registration, which displays the required OpenSSL commands."""

    http_method_names = ('get',)

    model = DevIdRegistration
    template_name = 'devices/help/onboarding/cmp_idevid_registration.html'
    context_object_name = 'devid_registration'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        devid_registration: DevIdRegistration = self.object

        if devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = (
                f'openssl genrsa -out domain_credential_key.pem {devid_registration.domain.public_key_info.key_size}'
            )
            key_gen_command = f'openssl genrsa -out key.pem {devid_registration.domain.public_key_info.key_size}'
        elif devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            domain_credential_key_gen_command = (
                f'openssl ecparam -name {devid_registration.domain.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem'
            )
            key_gen_command = (
                f'openssl ecparam -name {devid_registration.domain.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )
        else:
            err_msg = 'Unsupported public key algorithm'
            raise ValueError(err_msg)
        context['host'] = (f'{self.request.META.get("REMOTE_ADDR", "127.0.0.1")}:'
                           f'{self.request.META.get("SERVER_PORT", "443")}')
        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = (
            devid_registration.domain.issuing_ca.credential.get_certificate()
            .public_bytes(encoding=serialization.Encoding.PEM)
            .decode()
        )
        number_of_issued_device_certificates = 0
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'
        context['public_key_info'] = devid_registration.domain.public_key_info
        context['domain'] = devid_registration.domain
        return context


#  ----------------------------------- Certificate Lifecycle Management - Downloads ------------------------------------


class DownloadPageDispatcherView(DeviceContextMixin, SingleObjectMixin[IssuedCredentialModel], RedirectView):
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


class CertificateDownloadView(DeviceContextMixin, DetailView[IssuedCredentialModel]):
    """View for downloading certificates."""

    http_method_names = ('get',)

    model: type[IssuedCredentialModel] = IssuedCredentialModel
    template_name = 'devices/credentials/certificate_download.html'
    context_object_name = 'issued_credential'


class DeviceBaseCredentialDownloadView(
    DeviceContextMixin, DetailView[IssuedCredentialModel], FormView[CredentialDownloadForm]
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

        context['FileFormat'] = CredentialSerializer.FileFormat.__members__
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
            file_format = CredentialSerializer.FileFormat(self.request.POST.get('file_format'))
        except ValueError as exception:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg) from exception

        credential_model = issued_credential_model.credential
        credential_serializer = credential_model.get_credential_serializer()
        credential_purpose = IssuedCredentialModel.IssuedCredentialPurpose(
            issued_credential_model.issued_credential_purpose
        ).label
        credential_type_name = credential_purpose.replace(' ', '-').lower().replace('-credential', '')

        if file_format == CredentialSerializer.FileFormat.PKCS12:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pkcs12(password=password)),
                content_type='application/pkcs12',
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential.p12',
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_ZIP:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_zip(password=password)),
                content_type=ArchiveFormat.ZIP.mime_type,
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential{ArchiveFormat.ZIP.file_extension}',
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_TAR_GZ:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_tar_gz(password=password)),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential{ArchiveFormat.TAR_GZ.file_extension}',
            )

        else:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg)

        return cast('HttpResponse', response)


class DeviceManualCredentialDownloadView(DeviceBaseCredentialDownloadView):
    """View to download a password protected domain or application credential in the desired format."""


class DeviceBrowserOnboardingOTPView(DeviceContextMixin, DetailView[IssuedCredentialModel]):
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
                'device_name': device.unique_name,
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
        credential_id = cast(int, self.cleaned_data.get('credential_id'))
        credential_download = cast(RemoteDeviceCredentialDownloadModel, self.cleaned_data.get('credential_download'))
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


class DownloadTokenRequiredAuthenticationMixin(_DispatchableType):
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


class DeviceBrowserOnboardingCancelView(DeviceContextMixin, SingleObjectMixin[IssuedCredentialModel], RedirectView):
    """View to cancel the browser onboarding process and delete the associated RemoteDeviceCredentialDownloadModel."""

    http_method_names = ('get',)

    model = IssuedCredentialModel
    context_object_name = 'credential'
    object: IssuedCredentialModel
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


class DeviceRevocationView(DeviceContextMixin, FormMixin[CredentialRevocationForm], ListView[IssuedCredentialModel]):
    """Revokes all active credentials for a given device."""

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/revoke.html'
    context_object_name = 'credentials'
    form_class = CredentialRevocationForm
    success_url = reverse_lazy('devices:devices')
    device: DeviceModel

    def get_queryset(self) -> QuerySet[IssuedCredentialModel]:
        """Gets the queryset of all active credentials for the device."""
        self.device = get_object_or_404(DeviceModel, id=self.kwargs['pk'])
        qs = IssuedCredentialModel.objects.filter(device=self.device)
        for credential in qs:
            if credential.credential.certificate.certificate_status != CertificateModel.CertificateStatus.OK:
                qs = qs.exclude(pk=credential.pk)
        return qs

    def form_valid(self, form: CredentialRevocationForm) -> HttpResponse:
        """Performed if the form was validated successfully and revokes the credentials.

        Args:
            form: The corresponding form object.

        Returns:
            The Django HttpResponse object.
        """
        n_revoked = 0
        credentials = self.get_queryset()
        for credential in credentials:
            revoked_successfully, _msg = DeviceCredentialRevocation.revoke_certificate(
                credential.id, form.cleaned_data['revocation_reason']
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

        return super().form_valid(form)


class DeviceCredentialRevocationView(
    DeviceContextMixin,
    DetailView[IssuedCredentialModel],
    FormView[CredentialRevocationForm],
):
    """Revokes a specific issued credential."""

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/revoke.html'
    context_object_name = 'credential'
    pk_url_kwarg = 'credential_pk'
    form_class = CredentialRevocationForm

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the credential information to be revoked to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        context['credentials'] = [context['credential']]
        return context

    def get_success_url(self) -> str:
        """Gets the success url to redirect to after successful processing of the POST data following a form submit.

        Returns:
            The success url to redirect to after successful processing of the POST data following a form submit.
        """
        return str(reverse_lazy('devices:certificate_lifecycle_management', kwargs={'pk': self.get_object().device.id}))

    def form_valid(self, form: CredentialRevocationForm) -> HttpResponse:
        """Performed if the form was validated successfully and revokes the credential.

        Args:
            form: The corresponding form object.

        Returns:
            The Django HttpResponse object.
        """
        revoked_successfully, revocation_msg = DeviceCredentialRevocation.revoke_certificate(
            self.get_object().id, form.cleaned_data['revocation_reason']
        )

        if revoked_successfully:
            messages.success(self.request, revocation_msg)
        else:
            messages.error(self.request, revocation_msg)

        return super().form_valid(form)
