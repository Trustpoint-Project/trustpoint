"""Views for browser-based device onboarding workflows."""

from typing import Any, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_not_required
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.http.request import HttpRequest
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView

from devices.forms import (
    BrowserLoginForm,
)

# noinspection PyUnresolvedReferences
from devices.models import (
    RemoteDeviceCredentialDownloadModel,
)
from pki.models import IssuedCredentialModel
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
        if device is None:
            raise Http404
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
            *_args: Positional arguments are discarded.
            **_kwargs: Keyword arguments are discarded.

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
        messages.error(self.request, gettext_lazy('The provided password is not valid.'))
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
