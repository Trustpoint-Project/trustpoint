"""This module contains all views concerning the help pages used within the devices app."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from devices.models import DeviceModel, IssuedCredentialModel
from devices.views import (
    ActiveTrustpointTlsServerCredentialModelMissingErrorMsg,
    DeviceWithoutDomainErrorMsg,
    NamedCurveMissingForEccErrorMsg,
    PublicKeyInfoMissingErrorMsg,
)
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView
from django.views.generic.base import RedirectView
from django.views.generic.detail import DetailView, SingleObjectMixin
from pki.models.devid_registration import DevIdRegistration
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from settings.models import TlsSettings
from trustpoint_core import oid

from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any



#  ----------------------------------- Certificate Lifecycle Management - Help Pages -----------------------------------

class GetRedirectMixin:
    """Provides a get method that redirects to the ULR returned by get_redirect_url."""

    get_redirect_url: Callable[..., str]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Pro.

        Args:
            request: The django HttpRequest object.
            *args: Positional arguments are passed to self.get_redirect.url()
            **kwargs: Keyword arguments are passed to self.get_redirect.url()

        Returns:
            The corresponding redirect.
        """
        _ = request

        return HttpResponseRedirect(self.get_redirect_url(*args, **kwargs))


class DeviceHelpDispatchDomainCredentialView(PageContextMixin, GetRedirectMixin, DetailView[DeviceModel]):
    """Redirects to the required help pages depending on the onboarding protocol.

    If no help page could be determined, it will redirect to the devices page.
    """

    http_method_names = ('get',)

    model: type[DeviceModel] = DeviceModel
    permanent = False

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

    def get_redirect_url(self, *_args: Any, **_kwargs: Any) -> str:
        """Gets the redirection URL (Domain Credentials) for the required help page.

        Args:
            *args: Positional arguments are discarded.
            **kwargs: Keyword arguments are discarded.

        Returns:
            The redirection URL.
        """
        device: DeviceModel = self.get_object()

        if device.onboarding_protocol == device.OnboardingProtocol.CMP_SHARED_SECRET.value:
            return reverse(
                f'{self.page_category}:{self.page_name}_help-onboarding_cmp-shared-secret',
                kwargs={'pk': device.id})

        if device.onboarding_protocol == device.OnboardingProtocol.CMP_IDEVID.value:
            return reverse(
                f'{self.page_category}:{self.page_name}_help-onboarding_cmp-idevid',
                kwargs={'pk': device.id})

        if device.onboarding_protocol == device.OnboardingProtocol.EST_PASSWORD.value:
            return reverse(
                f'{self.page_category}:{self.page_name}_help-onboarding_est-username-password',
                kwargs={'pk': device.id})

        if device.onboarding_protocol == device.OnboardingProtocol.EST_IDEVID.value:
            return reverse(
                f'{self.page_category}:{self.page_name}_help-onboarding_est-idevid',
                kwargs={'pk': device.id})

        return reverse(f'{self.page_category}:{self.page_name}')


class OpcUaGdsHelpDispatchDomainCredentialView(PageContextMixin, GetRedirectMixin, DetailView[DeviceModel]):
    """Redirects to the required help pages depending on the onboarding protocol.

    If no help page could be determined, it will redirect to the devices page.
    """

    http_method_names = ('get',)

    model: type[DeviceModel] = DeviceModel
    permanent = False

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

    def get_redirect_url(self, *_args: Any, **_kwargs: Any) -> str:
        """Gets the redirection URL (Domain Credentials) for the required help page.

        Args:
            *args: Positional arguments are discarded.
            **kwargs: Keyword arguments are discarded.

        Returns:
            The redirection URL.
        """
        device: DeviceModel = self.get_object()

        if not device.domain_credential_onboarding and device.pki_protocol == device.PkiProtocol.EST_PASSWORD.value:
            return reverse(
                f'{self.page_category}:{self.page_name}_help-no-onboarding_est-username-password',
                kwargs={'pk': device.id})

        if device.onboarding_protocol == device.OnboardingProtocol.EST_PASSWORD.value:
            return reverse(
                f'{self.page_category}:{self.page_name}_help-onboarding_est-username-password',
                kwargs={'pk': device.id})

        return reverse(f'{self.page_category}:{self.page_name}')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Pro.

        Args:
            request: The django HttpRequest object.
            *args: Positional arguments are passed to self.get_redirect.url()
            **kwargs: Keyword arguments are passed to self.get_redirect.url()

        Returns:
            The corresponding redirect.
        """
        _ = request

        return HttpResponseRedirect(self.get_redirect_url(*args, **kwargs))


class AbstractDomainCredentialCmpHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Base view for CMP help views concerning the domain credential, not intended to be used directly."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        device: DeviceModel = self.object
        certificate_template = self.kwargs.get('certificate_template')
        context['certificate_template'] = certificate_template

        ipv4_address = TlsSettings.get_first_ipv4_address()

        context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'
        context['domain'] = device.domain
        context.update(self._get_domain_credential_cmp_context(device=device))

        if certificate_template is not None:
            number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
            camelcase_template = ''.join(word.capitalize() for word in certificate_template.split('-'))
            context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    @staticmethod
    def _get_domain_credential_cmp_context(device: DeviceModel) -> dict[str, Any]:
        """Provides the context for cmp commands using client based authentication.

        Args:
            device: The corresponding device model.

        Returns:
            The required context.
        """
        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)
        if not device.public_key_info:
            raise Http404(DeviceWithoutDomainErrorMsg)
        context = {}

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = (
                f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'
            )
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not device.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
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
            device.domain.get_issuing_ca_or_value_error()
            .credential.get_certificate()
            .public_bytes(encoding=serialization.Encoding.PEM)
            .decode()
        )
        return context

class DeviceOnboardingCmpSharedSecretHelpView(AbstractDomainCredentialCmpHelpView):
    """Help view for the onboarding cmp-shared secret case."""

    template_name = 'help/onboarding/cmp_shared_secret.html'

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY



class OpcUaGdsOnboardingCmpSharedSecretHelpView(AbstractDomainCredentialCmpHelpView):
    """Help view for the onboarding cmp-shared secret case."""

    template_name = 'help/onboarding/cmp_shared_secret.html'

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class DeviceOnboardingCmpIdevidHelpView(AbstractDomainCredentialCmpHelpView):
    """Help view for the onboarding IDeviD case."""

    template_name = 'help/onboarding/cmp_idevid.html'

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

class OpcUaGdsOnboardingCmpIdevidHelpView(AbstractDomainCredentialCmpHelpView):
    """Help view for the onboarding IDeviD case."""

    template_name = 'help/onboarding/cmp_idevid.html'

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class OnboardingCmpApplicationCredentialsHelpView(AbstractDomainCredentialCmpHelpView):
    """Help view for enrolling application credentials via CMP."""

    template_name = 'help/onboarding/cmp_application_credentials.html'


class AbstractDomainCredentialEstHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Base view for CMP help views concerning the domain credential, not intended to be used directly."""

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        device: DeviceModel = self.object
        certificate_template = self.kwargs.get('certificate_template')
        context['certificate_template'] = certificate_template
        ipv4_address = TlsSettings.get_first_ipv4_address()

        context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'

        context['domain'] = device.domain

        context.update(self._get_domain_credential_est_context(device=device))

        if certificate_template is not None:
            number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
            camelcase_template = ''.join(word.capitalize() for word in certificate_template.split('-'))
            context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    @staticmethod
    def _get_domain_credential_est_context(device: DeviceModel) -> dict[str, Any]:
        """Provides the context for est commands using client based authentication.

        Args:
            device: The corresponding device model.

        Returns:
            The required context.
        """
        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)
        if not device.public_key_info:
            raise Http404(DeviceWithoutDomainErrorMsg)
        context: dict[str, Any] = {}
        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = (
                f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'
            )
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not device.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
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
        if not tls_cert or not tls_cert.credential:
            raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
        context['trustpoint_server_certificate'] = (
            tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8')
        )

        context['domain_credential_cn'] = 'Trustpoint Domain Credential'

        return context


class DeviceOnboardingEstIdevidHelpView(AbstractDomainCredentialEstHelpView):
    """View to provide help information for EST IDevID enrollment."""

    template_name = 'help/onboarding/est_idevid.html'

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

class OpcUaGdsOnboardingEstIdevidHelpView(AbstractDomainCredentialEstHelpView):
    """View to provide help information for EST IDevID enrollment."""

    template_name = 'help/onboarding/est_idevid.html'

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class DeviceNoOnboardingEstUsernamePasswordHelpView(AbstractDomainCredentialEstHelpView):
    """View to provide help information for EST username/password authentication with no onboarding."""

    template_name = 'help/no_onboarding/est_username_password.html'
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingEstUsernamePasswordHelpView(AbstractDomainCredentialEstHelpView):
    """View to provide help information for EST username/password authentication with no onboarding and OPC UA GDS."""

    template_name = 'help/no_onboarding/est_gds_username_password.html'
    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class DeviceOnboardingEstUsernamePasswordHelpView(AbstractDomainCredentialEstHelpView):
    """View to provide help information for EST username/password authentication for onboarding."""

    template_name = 'help/onboarding/est_username_password.html'
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingEstUsernamePasswordHelpView(AbstractDomainCredentialEstHelpView):
    """View to provide help information for EST username/password authentication for onboarding."""

    template_name = 'help/onboarding/est_username_password.html'
    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY

class DeviceOnboardingEstApplicationCredentialsHelpView(AbstractDomainCredentialEstHelpView):
    """View to provide help information for EST domain credential authentication."""

    template_name = 'help/onboarding/est_application_credentials.html'
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY




# class AbstractHelpDispatchDeviceTypeRedirectView(PageContextMixin, DetailView[DeviceModel]):
#     """Redirects based on the device type: OPC UA GDS or standard device."""

#     http_method_names = ('get',)

#     model: type[DeviceModel] = DeviceModel
#     permanent = False

#     def get_redirect_url(self, *args: Any, **kwargs: Any) -> str:
#         """Determines the redirect URL based on the device type.

#         Args:
#             *args: Ignored positional arguments.
#             **kwargs: Should include 'pk' of the device to identify it.

#         Returns:
#             str: The URL to redirect to.
#         """
#         del args
#         device = get_object_or_404(DeviceModel, pk=kwargs.get('pk'))

#         if device.device_type == DeviceModel.DeviceType.OPC_UA_GDS.value:
#             return reverse('devices:help_dispatch_opcua_gds', kwargs={'pk': device.id})

#         return reverse('devices:help_dispatch_application', kwargs={'pk': device.id})


# class DeviceHelpDispatchDeviceTypeRedirectView(AbstractHelpDispatchDeviceTypeRedirectView):


class HelpDispatchApplicationCredentialView(TemplateView):
    """Renders the application credential selection page for the given device."""

    template_name = 'help/generic_details/application_credential_selection.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds device-related context to the template.

        Args:
            **kwargs: Keyword arguments containing the device's primary key (`pk`).

        Returns:
            A dictionary with context variables for the template.
        """
        context = super().get_context_data(**kwargs)

        device = get_object_or_404(DeviceModel, pk=kwargs.get('pk'))
        context['device'] = device

        return context


class HelpDispatchOpcUaGdsView(RedirectView):
    """Redirects to the required help page for OPC UA GDS devices."""

    http_method_names = ('get',)

    model: type[DeviceModel] = DeviceModel
    permanent = False

    def get_redirect_url(self, *args: Any, **kwargs: Any) -> str:
        """Gets the redirection URL for OPC UA GDS-specific help pages.

        Args:
            *args: Ignored positional arguments.
            **kwargs: Keyword arguments containing the device's primary key ('pk').

        Returns:
            str: The URL for the appropriate help page.

        Raises:
            Http404: If the device is not an OPC UA GDS device.
        """
        del args

        device = get_object_or_404(DeviceModel, pk=kwargs.get('pk'))

        if device.device_type != DeviceModel.DeviceType.OPC_UA_GDS.value:
            err_msg = 'This view only handles OPC UA GDS devices.'
            raise Http404(err_msg)

        if (
            not device.domain_credential_onboarding
            and device.pki_protocol == device.PkiProtocol.EST_PASSWORD.value
            and device.device_type == DeviceModel.DeviceType.OPC_UA_GDS.value
        ):
            return f'{reverse("devices:help-no-onboarding_est-opcua-gds-username-password", kwargs={"pk": device.id})}'

        return f'{reverse("devices:devices")}'


class HelpDispatchApplicationCredentialTemplateView(PageContextMixin, SingleObjectMixin[DeviceModel], RedirectView):
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

        device: DeviceModel = self.get_object()
        certificate_template = kwargs.get('certificate_template')

        if (
            not device.domain_credential_onboarding
            and device.pki_protocol == device.PkiProtocol.CMP_SHARED_SECRET.value
        ):
            return f'{
                reverse(
                    "devices:help_no-onboarding_cmp-shared-secret",
                    kwargs={"pk": device.id, "certificate_template": certificate_template},
                )
            }'

        if device.onboarding_protocol in {
            device.OnboardingProtocol.CMP_SHARED_SECRET.value,
            device.OnboardingProtocol.CMP_IDEVID.value,
        }:
            return f'{
                reverse(
                    "devices:help-onboarding_cmp-application-credentials",
                    kwargs={"pk": device.id, "certificate_template": certificate_template},
                )
            }'

        if (
            not device.domain_credential_onboarding
            and device.pki_protocol == device.PkiProtocol.EST_PASSWORD.value
            and device.device_type == DeviceModel.DeviceType.GENERIC_DEVICE.value
        ):
            return f'{
                reverse(
                    "devices:help-no-onboarding_est-username-password",
                    kwargs={"pk": device.id, "certificate_template": certificate_template},
                )
            }'

        if device.onboarding_protocol in {
            device.OnboardingProtocol.EST_PASSWORD.value,
        }:
            return f'{
                reverse(
                    "devices:help-onboarding_est-application-credentials",
                    kwargs={"pk": device.id, "certificate_template": certificate_template},
                )
            }'

        return f'{reverse("devices:devices")}'





class NoOnboardingCmpSharedSecretHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Help view for the case of no onboarding using CMP shared-secret."""

    http_method_names = ('get',)

    model = DeviceModel
    template_name = 'help/no_onboarding/cmp_shared_secret.html'
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
        certificate_template = self.kwargs.get('certificate_template')
        context['certificate_template'] = certificate_template
        if not device.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not device.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
            key_gen_command = (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )
        else:
            err_msg = _('Unsupported public key algorithm')
            raise ValueError(err_msg)

        ipv4_address = TlsSettings.get_first_ipv4_address()

        context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'
        context['domain'] = device.domain
        context['key_gen_command'] = key_gen_command
        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        camelcase_template = ''.join(word.capitalize() for word in certificate_template.split('-'))
        context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'
        return context





class OnboardingMethodSelectIdevidHelpView(PageContextMixin, DetailView[DevIdRegistration]):
    """View to select the protocol for IDevID enrollment."""

    template_name = 'help/onboarding/idevid_method_select.html'
    context_object_name = 'devid_registration'
    model = DevIdRegistration

    # TODO
    page_category = 'pki'
    page_name = 'domains'


class AbstractOnboardingIdevidRegistrationHelpView(PageContextMixin, DetailView[DevIdRegistration]):
    """Help view for the IDevID Registration, which displays the required OpenSSL commands."""

    http_method_names = ('get',)

    model = DevIdRegistration
    context_object_name = 'devid_registration'

    page_category = 'pki'
    page_name = 'domains'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        context['pk'] = self.kwargs.get('pk')
        devid_registration: DevIdRegistration = self.object

        if devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            domain_credential_key_gen_command = (
                f'openssl genrsa -out domain_credential_key.pem {devid_registration.domain.public_key_info.key_size}'
            )
            key_gen_command = f'openssl genrsa -out key.pem {devid_registration.domain.public_key_info.key_size}'
        elif devid_registration.domain.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not devid_registration.domain.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
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

        ipv4_address = TlsSettings.get_first_ipv4_address()

        context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'
        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = (
            devid_registration.domain.get_issuing_ca_or_value_error()
            .credential.get_certificate()
            .public_bytes(encoding=serialization.Encoding.PEM)
            .decode()
        )
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert or not tls_cert.credential:
            raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
        context['trustpoint_server_certificate'] = (
            tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8')
        )
        context['public_key_info'] = devid_registration.domain.public_key_info
        context['domain'] = devid_registration.domain
        return context


class OnboardingCmpIdevidRegistrationHelpView(AbstractOnboardingIdevidRegistrationHelpView):
    """Help view for the CMP IDevID Registration, which displays the required OpenSSL commands."""

    template_name = 'help/onboarding/cmp_idevid.html'


class OnboardingEstIdevidRegistrationHelpView(AbstractOnboardingIdevidRegistrationHelpView):
    """Help view for the EST IDevID Registration, which displays the required OpenSSL commands."""

    template_name = 'help/onboarding/est_idevid.html'



