"""Views for downloading device credentials and certificates."""

import io
from typing import Any, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.http import FileResponse, Http404, HttpResponse, HttpResponseBase
from django.http.request import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView
from trustpoint_core.archiver import Archiver
from trustpoint_core.serializer import CredentialFileFormat

from devices.forms import (
    CredentialDownloadForm,
)

# noinspection PyUnresolvedReferences
from devices.models import RemoteDeviceCredentialDownloadModel
from pki.models import IssuedCredentialModel
from pki.models.credential import CredentialModel
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)

DeviceWithoutDomainErrorMsg = gettext_lazy('Device does not have an associated domain.')
NamedCurveMissingForEccErrorMsg = gettext_lazy('Failed to retrieve named curve for ECC algorithm.')
ActiveTrustpointTlsServerCredentialModelMissingErrorMsg = gettext_lazy(
    'No active trustpoint TLS server credential found.'
)

# This only occurs if no domain is configured
PublicKeyInfoMissingErrorMsg = DeviceWithoutDomainErrorMsg

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

        cert_profile_name = issued_credential.issued_using_cert_profile

        domain_credential_value = IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL.value
        application_credential_value = IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL.value

        if issued_credential.issued_credential_type == domain_credential_value:
            context['credential_type'] = cert_profile_name

        elif issued_credential.issued_credential_type == application_credential_value:
            context['credential_type'] = cert_profile_name + ' Credential'

        else:
            err_msg = 'Unknown IssuedCredentialType'
            raise Http404(err_msg)

        context['FileFormat'] = CredentialFileFormat.__members__
        context['is_browser_dl'] = self.is_browser_download
        context['show_browser_dl'] = not self.is_browser_download
        context['issued_credential'] = issued_credential
        context['suggested_password'] = CredentialDownloadForm.get_suggested_password()

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
            _request: The django request object.
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
                err_msg = gettext_lazy('Unknown file format.')
                raise Http404(err_msg) from exception

            credential_model = self.object.credential
            credential_serializer = credential_model.get_credential_serializer()

            private_key_serializer = credential_serializer.get_private_key_serializer()
            certificate_serializer = credential_serializer.get_certificate_serializer()
            cert_collection_serializer = credential_serializer.get_additional_certificates_serializer()
            if not private_key_serializer or not certificate_serializer or not cert_collection_serializer:
                raise Http404

            cert_profile_name = self.object.issued_using_cert_profile
            credential_type_name = cert_profile_name.replace(' ', '-').lower().replace('-credential', '')

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
                err_msg = gettext_lazy('Unknown file format.')
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


class OpcUaGdsPushDownloadPageDispatcherView(AbstractDownloadPageDispatcherView):
    """Download dispatcher view for the OPC UA GDS Push pages."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


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


class OpcUaGdsPushCertificateDownloadView(AbstractCertificateDownloadView):
    """Certificate download view for the OPC UA GDS Push pages."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


