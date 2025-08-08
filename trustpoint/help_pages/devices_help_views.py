"""This module contains all views concerning the help pages used within the devices app."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
)
from devices.views import (
    ActiveTrustpointTlsServerCredentialModelMissingErrorMsg,
    DeviceWithoutDomainErrorMsg,
    NamedCurveMissingForEccErrorMsg,
    PublicKeyInfoMissingErrorMsg,
)
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
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
        __ = request

        return HttpResponseRedirect(self.get_redirect_url(*args, **kwargs))


class AbstractNoOnboardingCmpSharedSecretHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Help view for the case of no onboarding using CMP shared-secret."""

    http_method_names = ('get',)

    model = DeviceModel
    template_name = 'help/no_onboarding/cmp_shared_secret.html'
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

        context['key_gen_command'] = self._get_key_gen_command()

        if not device.no_onboarding_config:
            err_msg = _('Device is configured for onboarding.')
            raise Http404(err_msg)

        context['cmp_shared_secret'] = device.no_onboarding_config.cmp_shared_secret
        number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
        camelcase_template = ''.join(word.capitalize() for word in (certificate_template or 'Missing').split('-'))

        context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'
        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_key_gen_command(self) -> str:
        device: DeviceModel = self.object

        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not device.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            return f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not device.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
            return (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )

        err_msg = _('Unsupported public key algorithm')
        raise ValueError(err_msg)


class DeviceNoOnboardingCmpSharedSecretHelpView(AbstractNoOnboardingCmpSharedSecretHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingCmpSharedSecretHelpView(AbstractNoOnboardingCmpSharedSecretHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractCredentialEstHelpView(PageContextMixin, DetailView[DeviceModel]):
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

        context['key_gen_command'] = self._get_key_gen_command()
        context['domain_credential_key_gen_command'] = self._get_domain_credential_key_gen_command()

        context['domain_credential_cn'] = 'Trustpoint Domain Credential'
        context['trustpoint_server_certificate'] = self._get_tls_server_cert()

        if certificate_template is not None:
            number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
            camelcase_template = ''.join(word.capitalize() for word in certificate_template.split('-'))
            context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_key_gen_command(self) -> str:
        device: DeviceModel = self.object
        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not device.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            return f'openssl genrsa -out key.pem {device.public_key_info.key_size}'

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not device.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
            return (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out key.pem'
            )

        err_msg = _('Unsupported public key algorithm')
        raise ValueError(err_msg)

    def _get_domain_credential_key_gen_command(self) -> str:
        device: DeviceModel = self.object
        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not device.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
            return f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'

        if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
            if not device.public_key_info.named_curve:
                raise Http404(NamedCurveMissingForEccErrorMsg)
            return (
                f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
                f'-genkey -noout -out domain_credential_key.pem'
            )

        err_msg = _('Unsupported public key algorithm')
        raise ValueError(err_msg)

    def _get_tls_server_cert(self) -> str:
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert or not tls_cert.credential:
            raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
        return tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8')


class DeviceNoOnboardingEstUsernamePasswordHelpView(AbstractCredentialEstHelpView):
    """View to provide help information for EST username/password authentication with no onboarding."""

    template_name = 'help/no_onboarding/est_username_password.html'
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingEstUsernamePasswordHelpView(AbstractCredentialEstHelpView):
    """View to provide help information for EST username/password authentication with no onboarding and OPC UA GDS."""

    template_name = 'help/no_onboarding/est_gds_username_password.html'
    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class DeviceOnboardingEstUsernamePasswordHelpView(AbstractCredentialEstHelpView):
    """View to provide help information for EST username/password authentication for onboarding."""

    template_name = 'help/onboarding/est_username_password.html'
    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingEstUsernamePasswordHelpView(AbstractCredentialEstHelpView):
    """View to provide help information for EST username/password authentication for onboarding."""

    template_name = 'help/onboarding/est_username_password.html'
    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class HelpDomainCredentialCmpContextView(DetailView[DeviceModel]):
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

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        if certificate_template is not None:
            number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
            camelcase_template = ''.join(word.capitalize() for word in certificate_template.split('-'))
            context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'

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

        if not device.onboarding_config:
            err_msg = _('Device is not configured for onboarding.')
            raise Http404(err_msg)
        context['cmp_shared_secret'] = device.onboarding_config.onboarding_cmp_shared_secret
        context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
        context['key_gen_command'] = key_gen_command
        context['issuing_ca_pem'] = (
            device.domain.get_issuing_ca_or_value_error().credential.get_certificate()
            .public_bytes(encoding=serialization.Encoding.PEM)
            .decode()
        )
        return context


class DeviceOnboardingCmpSharedSecretHelpView(HelpDomainCredentialCmpContextView):
    """Help view for the onboarding cmp-shared secret case."""

    template_name = 'help/onboarding/cmp_shared_secret.html'

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingCmpSharedSecretHelpView(HelpDomainCredentialCmpContextView):
    """Help view for the onboarding cmp-shared secret case."""

    template_name = 'help/onboarding/cmp_shared_secret.html'

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
