"""This module contains all views concerning the devices application."""

from __future__ import annotations

import datetime
import io
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives import serialization

from core.file_builder.enum import ArchiveFormat
from core.serializer import CredentialSerializer
from core.validator.field import UniqueNameValidator
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.forms import BaseModelForm
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView, SingleObjectMixin
from django.views.generic.edit import CreateView, FormMixin, FormView
from django.views.generic.list import ListView
from core import oid
from pki.models import CertificateModel, CredentialModel, DevIdRegistration

from devices.forms import (
    BrowserLoginForm,
    CredentialDownloadForm,
    CredentialRevocationForm,
    IssueTlsClientCredentialForm,
    IssueTlsServerCredentialForm,
    CreateDeviceForm
)
from devices.issuer import LocalTlsClientCredentialIssuer, LocalTlsServerCredentialIssuer
from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
    RemoteDeviceCredentialDownloadModel)
from devices.revocation import DeviceCredentialRevocation
from trustpoint.settings import UIConfig
from trustpoint.views.base import ListInDetailView, SortableTableMixin, TpLoginRequiredMixin

if TYPE_CHECKING:
    from typing import Any, ClassVar

    from django.http.request import HttpRequest
    from django.utils.safestring import SafeString


class Detail404RedirectView(DetailView):
    """A detail view that redirects to self.redirection_view on 404 and adds a message."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Overrides the get method to add a message and redirect to self.redirection_view on 404."""
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            redirection_view = 'devices:devices'
            messages.error(
                self.request, f'{self.model.__name__} with ID {kwargs[self.pk_url_kwarg]} not found.'
            )
            return redirect(redirection_view)


class DeviceContextMixin:
    """Mixin which adds context_data for the Devices -> Devices pages."""

    extra_context: ClassVar = {'page_category': 'devices', 'page_name': 'devices'}


class DownloadTokenRequiredMixin:
    """Mixin which checks the token included in the URL for browser download views."""

    credential_download: RemoteDeviceCredentialDownloadModel

    def dispatch(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:
        """Checks the validity of the token included in the URL for browser download views."""
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


class DeviceTableView(DeviceContextMixin, TpLoginRequiredMixin, SortableTableMixin, ListView):
    """Device Table View."""

    model = DeviceModel
    template_name = 'devices/devices.html'
    context_object_name = 'devices'
    paginate_by = UIConfig.paginate_by
    default_sort_param = 'unique_name'

    def get_context_data(self, **kwargs: dict[str, Any]) -> dict[str, Any]:
        """Add the context data for the view and render additional table fields."""
        context = super().get_context_data(**kwargs)

        for device in context['page_obj']:
            device.onboarding_button = self._render_onboarding_button(device)
            device.clm_button = self._render_clm(device)
            device.revoke_button = self._render_revoke(device)

        return context

    @staticmethod
    def _render_onboarding_button(record: any) -> SafeString | str:
        """Creates the html hyperlink for the onboarding-view.

        Args:
            record (Device): The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the details-view.
        """
        if not record.domain:
            return format_html(
                '<span>{}</span>', _('No Domain configured.'))
        if not record.domain.issuing_ca:
            return format_html(
                '<span>{}</span>', _('No Issuing CA configured.')
            )
        return 'Hello'

    @staticmethod
    def _render_clm(record: DeviceModel) -> SafeString | str:
        return format_html(
            f'<a href="certificate-lifecycle-management/{record.pk}/" class="btn btn-primary tp-table-btn w-100">Manage</a>',
        )

    @staticmethod
    def _render_revoke(record: DeviceModel) -> SafeString | str:
        # TODO(Air): This cursed query may be slow for a large number of devices.
        if IssuedCredentialModel.objects.filter(device=record,
                                                credential__primarycredentialcertificate__is_primary=True).exists():
            return format_html('<a href="revoke/{}/" class="btn btn-danger tp-table-btn w-100">{}</a>',
                               record.pk, _('Revoke'))

        return format_html('<a class="btn btn-danger tp-table-btn w-100 disabled">{}</a>', _('Revoke'))



class CreateDeviceView(DeviceContextMixin, TpLoginRequiredMixin, CreateView):
    """Device Create View."""

    http_method_names = ('get', 'post')
    model = DeviceModel
    form_class = CreateDeviceForm
    template_name = 'devices/add.html'

    def get_success_url(self) -> str:
        return reverse('devices:help_dispatch', kwargs={'pk': self.object.id })

    @staticmethod
    def clean_device_name(device_name: str) -> str:
        """Validates the device name, i.e. checks if it is unique.

        Args:
            device_name: The desired name of the new device.

        Returns:
            The device name if it passed the checks.
        """
        UniqueNameValidator(device_name)
        return device_name

    def form_valid(self, form: BaseModelForm[DeviceModel]) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new TLS server credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """

        return super().form_valid(form)


class NoOnboardingCmpSharedSecretHelpView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView[DeviceModel]):

    model = DeviceModel
    template_name = 'devices/help/no_onboarding/cmp_shared_secret.html'
    context_object_name = 'device'

    def get_context_data(self, **kwargs) -> dict[str, Any]:
        context = super().get_context_data()
        device: DeviceModel = self.object

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem')
        else:
            raise ValueError('Unsupported public key algorithm')
        context['host'] = self.request.META.get('REMOTE_ADDR') + ':' + self.request.META.get('SERVER_PORT')
        context['key_gen_command'] = key_gen_command
        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'
        return context


class OnboardingCmpSharedSecretHelpView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView[DeviceModel]):

    model = DeviceModel
    template_name = 'devices/help/onboarding/cmp_shared_secret.html'
    context_object_name = 'device'

    def get_context_data(self, **kwargs) -> dict[str, Any]:
        context = super().get_context_data()
        device: DeviceModel = self.object

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            domain_credential_key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem')
            key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem')
        else:
            raise ValueError('Unsupported public key algorithm')
        context['host'] = self.request.META.get('REMOTE_ADDR') + ':' + self.request.META.get('SERVER_PORT')
        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = device.domain.issuing_ca.credential.get_certificate().public_bytes(
            encoding=serialization.Encoding.PEM).decode()
        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'
        return context


class OnboardingCmpIdevidHelpView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView[DeviceModel]):

    model = DeviceModel
    template_name = 'devices/help/onboarding/cmp_idevid.html'
    context_object_name = 'device'

    def get_context_data(self, **kwargs) -> dict[str, Any]:
        context = super().get_context_data()
        device: DeviceModel = self.object

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            domain_credential_key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem')
            key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem')
        else:
            raise ValueError('Unsupported public key algorithm')
        context['host'] = self.request.META.get('REMOTE_ADDR') + ':' + self.request.META.get('SERVER_PORT')
        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = device.domain.issuing_ca.credential.get_certificate().public_bytes(
            encoding=serialization.Encoding.PEM).decode()
        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'
        return context


class DeviceDetailsView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView[DeviceModel]):
    """Device Details View."""

    http_method_names = ('get',)

    model = DeviceModel
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/details.html'
    context_object_name = 'device'


class DeviceConfigureView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView[DeviceModel]):
    """Device Configuration View."""

    http_method_names = ('get',)

    model = DeviceModel
    success_url = reverse_lazy('devices:devices')
    template_name = 'devices/configure.html'
    context_object_name = 'device'


class DeviceBaseCredentialDownloadView(DeviceContextMixin,
                                       Detail404RedirectView[IssuedCredentialModel],
                                       FormView[CredentialDownloadForm]
):
    """View to download a password protected application credential in the desired format.

    Inherited by the domain and application credential download views.
    """

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/credentials/credential_download.html'
    form_class = CredentialDownloadForm
    context_object_name = 'credential'
    is_browser_download = False

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data depending on the credential.

        Args:
            **kwargs: Keyword arguments are passed to super().get_context_data(**kwargs).

        Returns:
            The context data for the view.
        """
        context = super().get_context_data(**kwargs)
        issued_credential = self.get_object()
        credential = issued_credential.credential

        if credential.credential_type != CredentialModel.CredentialTypeChoice.ISSUED_CREDENTIAL: # sanity check
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

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all POST requests, i.e. the expected form data.

        Args:
            request: The POST request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form: CredentialDownloadForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to start the download process of the desired file.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            If successful, this will start the file download. Otherwise, a Http404 will be raised and displayed.
        """
        self.object = self.get_object()

        password = form.cleaned_data['password'].encode()

        try:
            file_format = CredentialSerializer.FileFormat(self.request.POST.get('file_format'))
        except ValueError:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg) from ValueError

        credential_model = self.get_object().credential
        credential_serializer = credential_model.get_credential_serializer()
        credential_purpose = IssuedCredentialModel.IssuedCredentialPurpose(
            self.get_object().issued_credential_purpose
        ).label
        credential_type_name = credential_purpose.replace(' ', '-').lower().replace('-credential', '')

        if file_format == CredentialSerializer.FileFormat.PKCS12:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pkcs12(password=password)),
                content_type='application/pkcs12',
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential.p12')

        elif file_format == CredentialSerializer.FileFormat.PEM_ZIP:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_zip(password=password)),
                content_type=ArchiveFormat.ZIP.mime_type,
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential{ArchiveFormat.ZIP.file_extension}'
            )

        elif file_format == CredentialSerializer.FileFormat.PEM_TAR_GZ:
            response = FileResponse(
                io.BytesIO(credential_serializer.as_pem_tar_gz(password=password)),
                content_type=ArchiveFormat.TAR_GZ.mime_type,
                as_attachment=True,
                filename=f'trustpoint-{credential_type_name}-credential{ArchiveFormat.TAR_GZ.file_extension}')

        else:
            err_msg = _('Unknown file format.')
            raise Http404(err_msg)

        return cast('HttpResponse', response)


class DeviceManualCredentialDownloadView(TpLoginRequiredMixin, DeviceBaseCredentialDownloadView):
    """View to download a password protected domain or application credential in the desired format.

    This CBV does intentionally not require the authentication mixin.
    """


class DeviceBrowserCredentialDownloadView(DownloadTokenRequiredMixin, DeviceBaseCredentialDownloadView):
    """View to download a password protected domain or app credential in the desired format from a remote client.

    This CBV does intentionally not require the authentication mixin.
    """

    is_browser_download = True


class DeviceIssueTlsClientCredential(
    DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel], FormView[IssueTlsClientCredentialForm]
):
    """View to issue a new TLS client credential."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'
    form_class = IssueTlsClientCredentialForm

    def get_initial(self) -> dict[str, Any]:
        """Gets the initial data for the form.

        Returns:
            Dictionary containing the initial form data.
        """
        initial = super().get_initial()
        device = self.get_object()
        initial.update(LocalTlsClientCredentialIssuer.get_fixed_values(device=device, domain=device.domain))
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        form_kwargs = super().get_form_kwargs()
        form_kwargs.update({'device': self.get_object()})
        return form_kwargs

    def get_success_url(self) -> str:
        """Returns the URL to redirect to if the form is valid and was successfully processed."""
        kwargs = {'pk': self.get_object().id}
        return cast('str', reverse_lazy('devices:certificate_lifecycle_management', kwargs=kwargs))

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all POST requests, i.e. the expected form data.

        Args:
            request: The POST request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form: IssueTlsClientCredentialForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new TLS client credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            The HttpResponse that will display the CLM summary view.
        """
        device = self.get_object()
        common_name = cast('str', form.cleaned_data.get('common_name'))
        validity = cast('int', form.cleaned_data.get('validity'))

        tls_client_issuer = LocalTlsClientCredentialIssuer(device=device, domain=device.domain)
        _ = tls_client_issuer.issue_tls_client_credential(common_name=common_name, validity_days=validity)
        messages.success(
            self.request, 'Successfully issued TLS Client credential device ' f'{tls_client_issuer.device.unique_name}'
        )
        return super().form_valid(form)


class DeviceIssueTlsServerCredential(
    DeviceContextMixin, TpLoginRequiredMixin, DetailView[DeviceModel], FormView[IssueTlsServerCredentialForm]
):
    """View to issue a new TLS server credential."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    context_object_name = 'device'
    template_name = 'devices/credentials/issue_application_credential.html'
    form_class = IssueTlsServerCredentialForm

    def get_initial(self) -> dict[str, Any]:
        """Gets the initial data for the form.

        Returns:
            Dictionary containing the initial form data.
        """
        initial = super().get_initial()
        device = self.get_object()
        initial.update(LocalTlsServerCredentialIssuer.get_fixed_values(device=device, domain=device.domain))
        return initial

    def get_form_kwargs(self) -> dict[str, Any]:
        form_kwargs = super().get_form_kwargs()
        form_kwargs.update({'device': self.get_object()})
        return form_kwargs

    def get_success_url(self) -> str:
        """Returns the URL to redirect to if the form is valid and was successfully processed."""
        kwargs = {'pk': self.get_object().id}
        return cast('str', reverse_lazy('devices:certificate_lifecycle_management', kwargs=kwargs))

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all POST requests, i.e. the expected form data.

        Args:
            request: The POST request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        self.object = self.get_object()
        return FormView.post(self, request, *args, **kwargs)

    def form_valid(self, form: IssueTlsServerCredentialForm) -> HttpResponse:
        """Processing the valid form data.

        This will use the contained form data to issue a new TLS server credential.

        Args:
            form: The valid form including the cleaned data.

        Returns:
            The HttpResponse that will display the CLM summary view.
        """
        device = self.get_object()

        common_name = cast('str', form.cleaned_data.get('common_name'))
        ipv4_addresses = cast('list[ipaddress.IPv4Address]', form.cleaned_data.get('ipv4_addresses'))
        ipv6_addresses = cast('list[ipaddress.IPv6Address]', form.cleaned_data.get('ipv6_addresses'))
        domain_names = cast('list[str]', form.cleaned_data.get('domain_names'))
        validity = cast('int', form.cleaned_data.get('validity'))

        if not common_name:
            raise Http404

        tls_server_credential_issuer = LocalTlsServerCredentialIssuer(device=device, domain=device.domain)
        _ = tls_server_credential_issuer.issue_tls_server_credential(
            common_name=common_name,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
            domain_names=domain_names,
            validity_days=validity,
        )
        messages.success(
            self.request,
            'Successfully issued TLS Server credential device ' f'{tls_server_credential_issuer.device.unique_name}',
        )

        return super().form_valid(form)


class DeviceCertificateLifecycleManagementSummaryView(
    DeviceContextMixin, TpLoginRequiredMixin, SortableTableMixin, ListInDetailView[DeviceModel]
):
    """This is the CLM summary view in the devices section."""

    http_method_names = ('get',)

    detail_model = DeviceModel
    template_name = 'devices/credentials/certificate_lifecycle_management.html'
    detail_context_object_name = 'device'
    model = IssuedCredentialModel
    context_object_name = 'issued_credentials'
    default_sort_param = 'common_name'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        device = self.get_object()
        qs = super().get_queryset() # inherited from SortableTableMixin, sorted query

        domain_credentials = qs.filter(
            Q(device=device) &
            Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value)
        )

        application_credentials = qs.filter(
            Q(device=device) &
            Q(issued_credential_type=IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value)
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
            cred.expires_in = self._render_expires_in(cred)
            cred.expiration_date = self._render_expiration_date(cred)
            cred.revoke = self._render_revoke(cred)

        for cred in context['application_credentials']:
            cred.expires_in = self._render_expires_in(cred)
            cred.expiration_date = self._render_expiration_date(cred)
            cred.revoke = self._render_revoke(cred)

        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Processing of all GET requests.

        Args:
            request: The GET request to process.
            *args: Any positional arguments are passed to super().get().
            **kwargs: Any keyword arguments are passed to super().get().

        Returns:
            The HttpResponse to display the view.
        """
        return super().get(request, *args, **kwargs)

    @staticmethod
    def _render_expiration_date(record: IssuedCredentialModel) -> datetime.datetime:
            return record.credential.certificate.not_valid_after

    @staticmethod
    def _render_expires_in(record: IssuedCredentialModel) -> str | SafeString:
        if record.credential.certificate.certificate_status != CertificateModel.CertificateStatus.OK:
            return record.credential.certificate.certificate_status.label
        now = datetime.datetime.now(datetime.timezone.utc)
        expire_timedelta = record.credential.certificate.not_valid_after - now
        days = expire_timedelta.days
        hours, remainder = divmod(expire_timedelta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return format_html(f'{days} days, {hours}:{minutes:02d}:{seconds:02d}')

    @staticmethod
    def _render_revoke(record: IssuedCredentialModel) -> SafeString:
        """Creates the html hyperlink for the revoke-view.

        Args:
            record: The current record of the Device model.

        Returns:
            SafeString: The html hyperlink for the revoke-view.
        """
        if record.credential.certificate.certificate_status == CertificateModel.CertificateStatus.REVOKED:
            return format_html('<a class="btn btn-danger tp-table-btn w-100 disabled">{}</a>', _('Revoked'))

        return format_html('<a href="revoke/{}/" class="btn btn-danger tp-table-btn w-100">{}</a>',
                           record.pk, _('Revoke'))


class DeviceRevocationView(DeviceContextMixin, TpLoginRequiredMixin, FormMixin, ListView):
    """Revokes all active credentials for a given device."""

    http_method_names = ('get', 'post')

    model = DeviceModel
    template_name = 'devices/revoke.html'
    context_object_name = 'credentials'
    form_class = CredentialRevocationForm
    success_url = reverse_lazy('devices:devices')
    device: DeviceModel

    def get_queryset(self):
        self.device = get_object_or_404(DeviceModel, id=self.kwargs['pk'])
        # TODO(Air): This query is cursed but works
        return IssuedCredentialModel.objects.filter(device=self.device,
                                                    credential__primarycredentialcertificate__is_primary=True)

    def post(self, request, *args, **kwargs):
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)

        return self.form_invalid(form)

    def form_valid(self, form) -> HttpResponse:
        """Handles revocation upon a POST request containing a valid form."""
        # Revoke all active credentials for the device
        n_revoked = 0
        credentials = self.get_queryset()
        for credential in credentials:
            revoked_successfully, _msg = DeviceCredentialRevocation.revoke_certificate(
                credential.id,
                form.cleaned_data['revocation_reason']
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


class DeviceCredentialRevocationView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView, FormView):
    """Revokes a specific issued credential."""

    http_method_names = ('get', 'post')

    model = IssuedCredentialModel
    template_name = 'devices/revoke.html'
    context_object_name = 'credential'
    pk_url_kwarg = 'credential_pk'
    form_class = CredentialRevocationForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['credentials'] = [context['credential']]
        return context

    def get_success_url(self) -> str:
        """Returns the URL to redirect to if the form is valid and was successfully processed."""
        kwargs = {'pk': self.get_object().device.id}
        return cast('str', reverse_lazy('devices:certificate_lifecycle_management', kwargs=kwargs))

    def form_valid(self, form) -> HttpResponse:
        """Handles revocation upon a POST request containing a valid form."""
        revoked_successfully, revocation_msg = DeviceCredentialRevocation.revoke_certificate(
            self.get_object().id,
            form.cleaned_data['revocation_reason']
        )

        if revoked_successfully:
            messages.success(self.request, revocation_msg)
        else:
            messages.error(self.request, revocation_msg)

        return super().form_valid(form)


class DeviceBrowserOnboardingOTPView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView, RedirectView):
    """View to display the OTP for remote credential download (aka. browser onboarding)."""

    model = IssuedCredentialModel
    template_name = 'devices/credentials/onboarding/browser/otp_view.html'
    redirection_view = 'devices:devices'
    context_object_name = 'credential'

    def get(self, request: HttpRequest, *args: dict, **kwargs: dict) -> HttpResponse:  # noqa: ARG002
        """Renders a template view for displaying the OTP."""
        credential = self.get_object()
        device = credential.device
        try: # remove a potential previous download model for this credential
            cdm = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=credential, device=device)
            cdm.delete()
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            pass
        cdm = RemoteDeviceCredentialDownloadModel(issued_credential_model=credential, device=device)
        cdm.save()

        context = {
            'device_name': device.unique_name,
            'device_id': device.id,
            'credential_id': credential.id,
            'otp': cdm.get_otp_display(),
            'download_url': request.build_absolute_uri(reverse('devices:browser_login')),
        }

        return render(request, self.template_name, context)


class DeviceBrowserOnboardingCancelView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView, RedirectView):
    """View to cancel the browser onboarding process and delete the associated RemoteDeviceCredentialDownloadModel."""

    model = IssuedCredentialModel
    redirection_view = 'devices:credential-download'
    context_object_name = 'credential'

    def get_redirect_url(self, *args: tuple, **kwargs: dict) -> str:  # noqa: ARG002
        """Returns the URL to redirect to after the browser onboarding process was canceled."""
        pk = self.kwargs.get('pk')
        return reverse(self.redirection_view, kwargs={'pk': pk})

    def get(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:  # noqa: ARG002
        """Cancels the browser onboarding process and deletes the associated RemoteDeviceCredentialDownloadModel."""
        credential = self.get_object()
        device = credential.device
        try:
            cdm = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=credential, device=device)
            cdm.delete()
            messages.info(request, 'The browser onboarding process was canceled.')
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            messages.error(request, 'The browser onboarding process was not found.')

        return redirect(self.get_redirect_url())


class DeviceOnboardingBrowserLoginView(FormView):
    """View to handle certificate download requests."""

    template_name = 'devices/credentials/onboarding/browser/login.html'
    form_class = BrowserLoginForm

    def fail_redirect(self) -> HttpResponse:
        """On login failure, redirect back to the login page with an error message."""
        messages.error(self.request, _('The provided password is not valid.'))
        return redirect(self.request.path)

    def post(self, request: HttpRequest, *args: tuple, **kwargs: dict) -> HttpResponse:  # noqa: ARG002
        """Handles POST request for browser login form submission."""
        form = BrowserLoginForm(request.POST)
        if not form.is_valid():
            return self.fail_redirect()

        cred_id = form.cleaned_data['cred_id']
        otp = form.cleaned_data['otp']
        try:
            credential_download = RemoteDeviceCredentialDownloadModel.objects.get(issued_credential_model=cred_id)
        except RemoteDeviceCredentialDownloadModel.DoesNotExist:
            return self.fail_redirect()

        if not credential_download.check_otp(otp):
            return self.fail_redirect()

        token = credential_download.download_token
        url = f"{reverse('devices:browser_domain_credential_download', kwargs={'pk': cred_id})}?token={token}"
        return redirect(url)


class HelpDispatchView(DeviceContextMixin, TpLoginRequiredMixin, SingleObjectMixin, RedirectView):

    model: type[DeviceModel] = DeviceModel
    permanent = False

    def get_redirect_url(self, *args: tuple, **kwargs: dict) -> str:

        device: DeviceModel = self.get_object()
        if not device.domain_credential_onboarding:
            if device.pki_protocol == device.PkiProtocol.CMP_SHARED_SECRET.value:
                return f'{reverse("devices:help_no-onboarding_cmp-shared-secret", kwargs={"pk": device.id})}'

        if device.onboarding_protocol == device.OnboardingProtocol.CMP_SHARED_SECRET.value:
            return f'{reverse("devices:help-onboarding_cmp-shared-secret", kwargs={"pk": device.id})}'

        if device.onboarding_protocol == device.OnboardingProtocol.CMP_IDEVID.value:
            return f'{reverse("devices:help-onboarding_cmp-idevid", kwargs={"pk": device.id})}'

        return f"{reverse('devices:devices')}"


class DownloadPageDispatcherView(DeviceContextMixin, TpLoginRequiredMixin, SingleObjectMixin, RedirectView):

    model: type[IssuedCredentialModel] = IssuedCredentialModel
    permanent = False

    def get_redirect_url(self, *args: tuple, **kwargs: dict) -> str:
        issued_credential: IssuedCredentialModel = self.get_object()
        if issued_credential.credential.private_key:
            return f'{reverse("devices:credential-download", kwargs={"pk": issued_credential.id})}'
        return f'{reverse("devices:certificate-download", kwargs={"pk": issued_credential.id})}'


class CertificateDownloadView(DeviceContextMixin, TpLoginRequiredMixin, DetailView):

    http_method_names = ('get',)

    model: type[IssuedCredentialModel] = IssuedCredentialModel
    template_name = 'devices/credentials/certificate_download.html'
    context_object_name = 'issued_credential'


class OnboardingIdevidRegistrationHelpView(DeviceContextMixin, TpLoginRequiredMixin, Detail404RedirectView[DevIdRegistration]):

    model = DevIdRegistration
    template_name = 'devices/help/onboarding/cmp_idevid_registration.html'
    context_object_name = 'devid_registration'

    def get_context_data(self, **kwargs) -> dict[str, Any]:
        context = super().get_context_data()
        devid_registration: DevIdRegistration = self.object

        if devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = f'openssl genrsa -out domain_credential_key.pem {devid_registration.domain.public_key_info.key_size}'
            key_gen_command = f'openssl genrsa -out key.pem {devid_registration.domain.public_key_info.key_size}'
        elif devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            domain_credential_key_gen_command = (
                f'openssl ecparam -name {devid_registration.domain.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem')
            key_gen_command = (
                f'openssl ecparam -name {devid_registration.domain.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem')
        else:
            raise ValueError('Unsupported public key algorithm')
        context['host'] = self.request.META.get('REMOTE_ADDR') + ':' + self.request.META.get('SERVER_PORT')
        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = devid_registration.domain.issuing_ca.credential.get_certificate().public_bytes(
            encoding=serialization.Encoding.PEM).decode()
        number_of_issued_device_certificates = 0
        context['tls_client_cn'] = f'Trustpoint-TLS-Client-Credential-{number_of_issued_device_certificates}'
        context['tls_server_cn'] = f'Trustpoint-TLS-Server-Credential-{number_of_issued_device_certificates}'
        context['public_key_info'] = devid_registration.domain.public_key_info
        context['domain'] = devid_registration.domain
        return context
