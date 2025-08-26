"""This module contains all views concerning the help pages used within the devices app."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
)
from devices.views import (
    ActiveTrustpointTlsServerCredentialModelMissingErrorMsg,
    DeviceWithoutDomainErrorMsg,
    NamedCurveMissingForEccErrorMsg,
    PublicKeyInfoMissingErrorMsg,
)
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils.safestring import mark_safe
from django.utils.html import format_html
from django.utils.translation import gettext as _non_lazy
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from settings.models import TlsSettings
from trustpoint_core import oid

from help_pages.commands import CmpSharedSecretCommandBuilder, KeyGenCommandBuilder, EstUsernamePasswordCommandBuilder
from help_pages.help_section import HelpPage, HelpRow, HelpSection, ValueRenderType
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any, Self

    from django.utils.safestring import SafeString
    from pki.models.domain import DomainModel


@dataclass(frozen=True)
class ApplicationCertificateProfileData:
    """The application certificate profile data class that holds both value an label."""

    name: str
    label: str

class ApplicationCertificateProfile(enum.Enum):
    """Allowed application credential profiles."""

    TLS_CLIENT = ApplicationCertificateProfileData('tls-client', 'TLS-Client Certificate')
    TLS_SERVER = ApplicationCertificateProfileData('tls-server', 'TLS-Server Certificate')
    OPC_UA_CLIENT = ApplicationCertificateProfileData('opc-ua-client', 'OPC-UA-Client Certificate')
    OPC_UA_SERVER = ApplicationCertificateProfileData('opc-ua-server', 'OPC-UA-Server Certificate')

    @property
    def name(self) -> str:
        """Return the name of the profile.

        Returns:
            The name of the profile.
        """
        return self.value.name

    @property
    def label(self) -> str:
        """Return the label of the profile.

        Returns:
            The label of the profile.
        """
        return self.value.label

    @classmethod
    def from_name(cls, name: str) -> Self:
        """Gets the ApplicationCertificateProfile matching the name.

        Returns:
            The matching ApplicationCertificateProfile.

        Raises:
            ValueError: If no matching ApplicationCertifiateProfile is found for the name provided.
        """
        for member in cls:
            if member.value.name == name:
                return member
        err_msg = f'No ApplicationCertificateProfile with name={name} found.'
        raise ValueError(err_msg)

    @classmethod
    def from_label(cls, label: str) -> Self:
        """Gets the ApplicationCertificateProfile matching the label.

        Returns:
            The matching ApplicationCertificateProfile.

        Raises:
            ValueError: If no matching ApplicationCertifiateProfile is found for the label provided.
        """
        for member in cls:
            if member.value.name == label:
                return member
        err_msg = f'No ApplicationCertificateProfile with name={label} found.'
        raise ValueError(err_msg)

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
    """Abstract help view for the case of no onboarding using CMP shared-secret."""

    template_name = 'help/help_page.html'

    pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    no_onboarding_config: NoOnboardingConfigModel

    certificate_profile: str
    host: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        if not self.object.no_onboarding_config:
            err_msg = _('Onboarding is configured for this device.')
            raise Http404(err_msg)
        self.no_onboarding_config = self.object.no_onboarding_config

        if not self.object.domain:
            err_msg = _('No domain is configured for this device.')
            raise Http404(err_msg)
        self.certificate_profile = self.kwargs.get('certificate_template')
        if not self.certificate_profile:
            err_msg = _('Failed to get certificate profile')
        self.host = (
            f'{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}/'
            f'.well-known/cmp/certification/{ self.object.domain.unique_name }/')


        help_page = HelpPage(heading=_non_lazy('Help - CMP Shared-Secret (HMAC)'), sections=[
            self._get_summary_section(),
            self._get_key_generation_section(),
            self._get_certificate_profile_select_section(),
            self._get_cmp_tls_client_profile_cmd_section(),
            self._get_cmp_tls_server_profile_cmd_section(hidden=True),
            self._get_cmp_opc_ua_client_profile_cmd_section(hidden=True),
            self._get_cmp_opc_ua_server_profile_cmd_section(hidden=True)
        ])

        context['help_page'] = help_page

        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_certificate_profile_select_section(self) -> HelpSection:
        cert_profile_select_row = HelpRow(
            key=_non_lazy('Certificate Profile'),
            value=self._get_cert_profile_select_input(),
            value_render_type=ValueRenderType.PLAIN
        )

        return HelpSection(
            heading=_non_lazy('Certificate Profile Selection'),
            rows=[cert_profile_select_row]
        )

    def _get_cmp_tls_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_tls_client_profile_command(
            host=self.host + 'tls-client/',
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_cmd_tls_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=cmp_command,
            value_render_type=ValueRenderType.CODE,
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for TLS Client Certificates'),
            rows=[openssl_cmd_tls_client_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name
        )

    def _get_cmp_tls_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_tls_server_profile_command(
            host=self.host + 'tls-server/',
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_cmd_tls_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=cmp_command,
            value_render_type=ValueRenderType.CODE,
            hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for TLS Server Certificates'),
            rows=[openssl_cmd_tls_server_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_SERVER.name
        )

    def _get_cmp_opc_ua_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_opc_ua_client_profile_command(
            host=self.host + 'opc-ua-client/',
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_cmd_opc_ua_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=cmp_command,
            value_render_type=ValueRenderType.CODE,
            hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for OPC-UA Client Certificates'),
            rows=[openssl_cmd_opc_ua_client_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.name
        )

    def _get_cmp_opc_ua_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_opc_ua_server_profile_command(
            host=self.host + 'opc-ua-server/',
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_cmd_opc_ua_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=cmp_command,
            value_render_type=ValueRenderType.CODE,
            hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for OPC-UA Server Certificates'),
            rows=[openssl_cmd_opc_ua_server_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.name
        )

    def _get_summary_section(self) -> HelpSection:
        if self.object.domain is None:
            raise ValueError
        certificate_request_url = (
            f'https://{self.host}<certificate_profile>/'
        )
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE
        )
        kid_row = HelpRow(
            key=_non_lazy('Key Identifier (KID)'),
            value=str(self.object.pk),
            value_render_type=ValueRenderType.CODE
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.object.public_key_info),
            value_render_type=ValueRenderType.CODE
        )
        shared_secret_row = HelpRow(
            key=('Shared-Secret'),
            value=self._get_shared_secret(),
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Summary'),
            rows=[
                url_row,
                kid_row,
                public_key_type_row,
                shared_secret_row]
            )

    def _get_cert_profile_select_input(self) -> SafeString:
        select_field = '<select id="cert-profile-select" class="form-select" aria-label="Certificate Profile Select">'
        for index, profile in enumerate(ApplicationCertificateProfile):
            if index == 0:
                select_field += format_html('<option value="{}" selected>{}</option>', profile.name, profile.label)
            else:
                select_field += format_html('<option value="{}">{}</option>', profile.name, profile.label)
        select_field += '</select>'

        return format_html(select_field)


    def _get_key_generation_section(self) -> HelpSection:
        key_generation_row = HelpRow(
            key=_non_lazy('Generate Key-Pair'),
            value=self._get_key_gen_command(),
            value_render_type=ValueRenderType.CODE
        )

        return HelpSection(
            heading=format_html(_non_lazy('Key Generation')),
            rows=[key_generation_row]
        )

    def _get_key_gen_command(self) -> str:
        device: DeviceModel = self.object
        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not device.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=device.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
            )
        except Exception as exception:
            raise Http404(exception) from exception

    def _get_cmp_issuer_root_ca_pk(self) -> None | int:
        domain = self.object.domain
        if not domain:
            err_msg = 'domain not configured'
            raise ValueError(err_msg)
        issuing_ca = domain.issuing_ca
        if not issuing_ca:
            err_msg = 'issuing ca not configured'
            raise ValueError(err_msg)
        root_ca_model = issuing_ca.credential.get_last_in_chain()
        if not root_ca_model:
            return None
        return root_ca_model.pk

    def _get_shared_secret(self) -> str:
        return self.no_onboarding_config.cmp_shared_secret


class DeviceNoOnboardingCmpSharedSecretHelpView(AbstractNoOnboardingCmpSharedSecretHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingCmpSharedSecretHelpView(AbstractNoOnboardingCmpSharedSecretHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY



class AbstractNoOnboardingEstUsernamePasswordHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Abstract help view for the case of no onboarding using CMP shared-secret."""

    template_name = 'help/help_page.html'

    pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    no_onboarding_config: NoOnboardingConfigModel
    domain: DomainModel

    certificate_profile: str
    host: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        if not self.object.no_onboarding_config:
            err_msg = _('Onboarding is configured for this device.')
            raise Http404(err_msg)
        self.no_onboarding_config = self.object.no_onboarding_config

        if not self.object.domain:
            err_msg = _('No domain is configured for this device.')
            raise Http404(err_msg)
        self.domain = self.object.domain
        self.certificate_profile = self.kwargs.get('certificate_template')
        if not self.certificate_profile:
            err_msg = _('Failed to get certificate profile')
        self.host = (
            f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}/'
        )


        help_page = HelpPage(heading=_non_lazy('Help - CMP Shared-Secret (HMAC)'), sections=[
            self._get_summary_section(),
            self._get_download_tls_trust_store_section(),
            self._get_key_generation_section(),
            self._get_certificate_profile_select_section(),
            self._get_cmp_tls_client_profile_cmd_section(),
            self._get_cmp_tls_server_profile_cmd_section(hidden=True),
            self._get_cmp_opc_ua_client_profile_cmd_section(hidden=True),
            self._get_cmp_opc_ua_server_profile_cmd_section(hidden=True),
            self._get_conversion_der_to_pem_section()
        ])

        context['help_page'] = help_page

        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_conversion_der_to_pem_section(self) -> HelpSection:
        conversion_cmd = EstUsernamePasswordCommandBuilder.get_conversion_der_pem_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        conversion_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=conversion_cmd,
            value_render_type=ValueRenderType.CODE
        )
        return HelpSection(
            heading='Convert the certificate from DER format to PEM format (Optional)',
            rows=[conversion_row]
        )

    def _get_certificate_profile_select_section(self) -> HelpSection:
        cert_profile_select_row = HelpRow(
            key=_non_lazy('Certificate Profile'),
            value=self._get_cert_profile_select_input(),
            value_render_type=ValueRenderType.PLAIN
        )

        return HelpSection(
            heading=_non_lazy('Certificate Profile Selection'),
            rows=[cert_profile_select_row]
        )

    def _get_enroll_row(self, certificate_profile: str) -> HelpRow:
        enroll_cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_command(
            est_username=self.object.common_name,
            est_password=self.no_onboarding_config.est_username_password,
            host=f'{ self.host }/.well-known/est/{ self.domain.unique_name }/{ certificate_profile }/simpleenroll/',
            domain_name=self.domain.unique_name,
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        return HelpRow(
            key=_non_lazy('Enroll certificate with curl'),
            value=enroll_cmd,
            value_render_type=ValueRenderType.CODE
        )

    def _get_cmp_tls_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_tls_client_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_tls_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for TLS Client Certificates'),
            rows=[
                openssl_req_cmd_tls_client_profile_row,
                self._get_enroll_row(certificate_profile='tls-client')
            ],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name
        )

    def _get_cmp_tls_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_tls_server_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_tls_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for TLS Server Certificates'),
            rows=[
                openssl_req_cmd_tls_server_profile_row,
                self._get_enroll_row(certificate_profile='tls-server')
            ],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_SERVER.name
        )

    def _get_cmp_opc_ua_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_client_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_opc_ua_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for OPC-UA Client Certificates'),
            rows=[
                openssl_req_cmd_opc_ua_client_profile_row,
                self._get_enroll_row(certificate_profile='opc-ua-client')
            ],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.name
        )

    def _get_cmp_opc_ua_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_server_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_opc_ua_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for OPC-UA Server Certificates'),
            rows=[
                openssl_req_cmd_opc_ua_server_profile_row,
                self._get_enroll_row(certificate_profile='opc-ua-server')
            ],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.name
        )

    def _get_summary_section(self) -> HelpSection:
        if self.object.domain is None:
            raise ValueError
        certificate_request_url = (
            f'https://{ self.host }/.well-known/est/'
            f'{ self.object.domain.unique_name }/<certificate_profile>/simpleenroll/'
        )
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.object.public_key_info),
            value_render_type=ValueRenderType.CODE
        )
        est_username_row = HelpRow(
            key=('EST-Username'),
            value=self.object.common_name,
            value_render_type=ValueRenderType.CODE,
        )
        if not self.object.no_onboarding_config:
            err_msg = 'Device configured for onboarding.'
            raise ValueError(err_msg)
        est_password = HelpRow(
            key=('EST-PasswordU'),
            value=self.object.no_onboarding_config.est_username_password,
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Summary'),
            rows=[
                url_row,
                public_key_type_row,
                est_username_row,
                est_password
            ]
        )

    def _get_cert_profile_select_input(self) -> SafeString:
        select_field = '<select id="cert-profile-select" class="form-select" aria-label="Certificate Profile Select">'
        for index, profile in enumerate(ApplicationCertificateProfile):
            if index == 0:
                select_field += format_html('<option value="{}" selected>{}</option>', profile.name, profile.label)
            else:
                select_field += format_html('<option value="{}">{}</option>', profile.name, profile.label)
        select_field += '</select>'

        return format_html(select_field)


    def _get_key_generation_section(self) -> HelpSection:
        key_generation_row = HelpRow(
            key=_non_lazy('Generate Key-Pair'),
            value=self._get_key_gen_command(),
            value_render_type=ValueRenderType.CODE
        )

        return HelpSection(
            heading=format_html(_non_lazy('Key Generation')),
            rows=[key_generation_row]
        )

    def _get_key_gen_command(self) -> str:
        device: DeviceModel = self.object
        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not device.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=device.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
            )
        except Exception as exception:
            raise Http404(exception) from exception

    def _get_cmp_issuer_root_ca_pk(self) -> None | int:
        domain = self.object.domain
        if not domain:
            err_msg = 'domain not configured'
            raise ValueError(err_msg)
        issuing_ca = domain.issuing_ca
        if not issuing_ca:
            err_msg = 'issuing ca not configured'
            raise ValueError(err_msg)
        root_ca_model = issuing_ca.credential.get_last_in_chain()
        if not root_ca_model:
            return None
        return root_ca_model.pk

    def _get_shared_secret(self) -> str:
        return self.no_onboarding_config.cmp_shared_secret

    # def _get_device_trust_store(self) -> HelpSection:
    #     rows: list[HelpRow] = []

    #     device_root_ca_cert_pk = self._get_cmp_issuer_root_ca_pk()
    #     if device_root_ca_cert_pk is None:
    #         err_msg = _('Failed to get Root CA certificate (CMP signer).')
    #         raise ValueError(err_msg)

    #     download_trust_store_row = HelpRow(
    #         key=_non_lazy('Download Device Trust-Store'),
    #         value=format_html(
    #             '<a href="{}" class="btn btn-primary w-100">{}</a>',
    #             reverse(
    #                 'pki:certificate-file-download-file-name',
    #                 kwargs={
    #                     'file_format': 'pem',
    #                     'pk': device_root_ca_cert_pk,
    #                     'file_name': 'device_trust_store.pem'
    #                 }
    #             ),
    #             _non_lazy('Download Device Trust-Store')
    #         ),
    #         value_render_type=ValueRenderType.PLAIN
    #     )
    #     rows.append(download_trust_store_row)

    #     return HelpSection(
    #         heading=_non_lazy('Device Trust-Store'),
    #         rows=rows
    #     )

    def _get_download_tls_trust_store_section(self) -> HelpSection:
        tls_cert_pk = self._get_tls_server_root_ca_pk()
        if tls_cert_pk is None:
            err_msg = _non_lazy('Failed to get the Trustpoint TLS Root Certificate.')
            raise ValueError(err_msg)

        download_tls_truststore_row = HelpRow(
            key=_non_lazy('Download TLS Truststore'),
            value=format_html(
                '<a href="{}" class="btn btn-primary w-100">{}</a>',
                reverse(
                    'pki:certificate-file-download-file-name',
                    kwargs={
                        'file_format': 'pem',
                        'pk': tls_cert_pk,
                        'file_name': f'trust-store-{ self.domain.unique_name }.pem'
                    }
                ),
                _non_lazy('Download Device Trust-Store')
            ),
            value_render_type=ValueRenderType.PLAIN
        )

        return HelpSection(
            heading=_non_lazy('Download TLS Truststore'),
            rows=[download_tls_truststore_row]
        )

    def _get_tls_server_root_ca_pk(self) -> None | int:
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert or not tls_cert.credential:
            raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
        root_ca_model = tls_cert.credential.get_last_in_chain()
        if not root_ca_model:
            return None
        return root_ca_model.pk

class DeviceNoOnboardingEstUsernamePasswordHelpView(AbstractNoOnboardingEstUsernamePasswordHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsNoOnboardingEstUsernamePasswordHelpView(AbstractNoOnboardingEstUsernamePasswordHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY











































# class AbstractCredentialIssuanceHelpView(PageContextMixin, DetailView[DeviceModel]):
#     """Base view for CMP help views concerning the domain credential, not intended to be used directly."""

#     http_method_names = ('get',)

#     model = DeviceModel
#     context_object_name = 'device'

#     page_category = DEVICES_PAGE_CATEGORY
#     page_name: str

#     def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
#         """Adds information about the required OpenSSL commands to the context.

#         Args:
#             **kwargs: Keyword arguments passed to super().get_context_data.

#         Returns:
#             The context to render the page.
#         """
#         context = super().get_context_data(**kwargs)
#         device: DeviceModel = self.object
#         certificate_template = self.kwargs.get('certificate_template')
#         context['certificate_template'] = certificate_template

#         ipv4_address = TlsSettings.get_first_ipv4_address()
#         context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'
#         context['domain'] = device.domain

#         context['key_gen_command'] = self._get_key_gen_command()
#         context['domain_credential_key_gen_command'] = self._get_domain_credential_key_gen_command()

#         context['domain_credential_cn'] = 'Trustpoint Domain Credential'
#         # context['trustpoint_server_certificate'] = self._get_tls_server_cert()

#         context['cmp_tls_client_command'] = format_html(
#             'openssl cmp \\<br>'
#             '-cmd cr \\<br>'
#             '-implicit_confirm \\<br>'
#             '-server https://{{ host }}/.well-known/cmp/certification/{{ device.domain }}/tls-client/ \\<br>'
#             '-tls_used \\<br>'
#             '-ref {{ device.id }} \\<br>'
#             '-secret pass:{{ cmp_shared_secret }} \\<br>'
#             '-subject "/CN={{ cn_entry }}" \\<br>'
#             '-days 10 \\<br>'
#             '-newkey key.pem \\<br>'
#             '-certout cert.pem \\<br>'
#             '-chainout chain_without_root.pem \\<br>'
#             '-extracertsout full_chain.pem'
#         )

#         if certificate_template is not None:
#             number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
#             camelcase_template = ''.join(word.capitalize() for word in certificate_template.split('-'))
#             context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'

#         context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

#         return context

#     def _get_key_gen_command(self) -> str:
#         device: DeviceModel = self.object
#         if device.domain is None:
#             raise Http404(DeviceWithoutDomainErrorMsg)

#         if not device.public_key_info:
#             raise Http404(PublicKeyInfoMissingErrorMsg)

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
#             return f'openssl genrsa -out key.pem {device.public_key_info.key_size}'

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
#             if not device.public_key_info.named_curve:
#                 raise Http404(NamedCurveMissingForEccErrorMsg)
#             return (
#                 f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
#                 f'-genkey -noout -out key.pem'
#             )

#         err_msg = _('Unsupported public key algorithm')
#         raise ValueError(err_msg)

#     def _get_domain_credential_key_gen_command(self) -> str:
#         device: DeviceModel = self.object
#         if device.domain is None:
#             raise Http404(DeviceWithoutDomainErrorMsg)

#         if not device.public_key_info:
#             raise Http404(PublicKeyInfoMissingErrorMsg)

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
#             return f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
#             if not device.public_key_info.named_curve:
#                 raise Http404(NamedCurveMissingForEccErrorMsg)
#             return (
#                 f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
#                 f'-genkey -noout -out domain_credential_key.pem'
#             )

#         err_msg = _('Unsupported public key algorithm')
#         raise ValueError(err_msg)

#     def _get_tls_server_cert(self) -> str:
#         tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
#         if not tls_cert or not tls_cert.credential:
#             raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
#         return tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8')


# class DeviceOnboardingEstUsernamePasswordHelpView(AbstractCredentialIssuanceHelpView):
#     """View to provide help information for EST username/password authentication for onboarding."""

#     template_name = 'help/deprecated/onboarding/est_username_password.html'
#     page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


# class OpcUaGdsOnboardingEstUsernamePasswordHelpView(AbstractCredentialIssuanceHelpView):
#     """View to provide help information for EST username/password authentication for onboarding."""

#     template_name = 'help/deprecated/onboarding/est_username_password.html'
#     page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


# class HelpDomainCredentialCmpContextView(PageContextMixin, DetailView[DeviceModel]):
#     """Base view for CMP help views concerning the domain credential, not intended to be used directly."""

#     http_method_names = ('get',)

#     model = DeviceModel
#     template_name: str
#     context_object_name = 'device'

#     page_category = DEVICES_PAGE_CATEGORY
#     page_name: str

#     def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
#         """Adds information about the required OpenSSL commands to the context.

#         Args:
#             **kwargs: Keyword arguments passed to super().get_context_data.

#         Returns:
#             The context to render the page.
#         """
#         context = super().get_context_data(**kwargs)
#         device: DeviceModel = self.object
#         certificate_template = self.kwargs.get('certificate_template')
#         context['certificate_template'] = certificate_template

#         ipv4_address = TlsSettings.get_first_ipv4_address()
#         context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'
#         context['domain'] = device.domain

#         context['key_gen_command'] = self._get_key_gen_command()
#         context['domain_credential_key_gen_command'] = self._get_domain_credential_key_gen_command()

#         context['domain_credential_cn'] = 'Trustpoint Domain Credential'
#         context['trustpoint_server_certificate'] = self._get_tls_server_cert()

#         if certificate_template is not None:
#             number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
#             camelcase_template = ''.join(word.capitalize() for word in certificate_template.split('-'))
#             context['cn_entry'] = f'Trustpoint-{camelcase_template}-Credential-{number_of_issued_device_certificates}'

#         context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

#         return context

#     def _get_key_gen_command(self) -> str:
#         device: DeviceModel = self.object
#         if device.domain is None:
#             raise Http404(DeviceWithoutDomainErrorMsg)

#         if not device.public_key_info:
#             raise Http404(PublicKeyInfoMissingErrorMsg)

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
#             return f'openssl genrsa -out key.pem {device.public_key_info.key_size}'

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
#             if not device.public_key_info.named_curve:
#                 raise Http404(NamedCurveMissingForEccErrorMsg)
#             return (
#                 f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
#                 f'-genkey -noout -out key.pem'
#             )

#         err_msg = _('Unsupported public key algorithm')
#         raise ValueError(err_msg)

#     def _get_domain_credential_key_gen_command(self) -> str:
#         device: DeviceModel = self.object
#         if device.domain is None:
#             raise Http404(DeviceWithoutDomainErrorMsg)

#         if not device.public_key_info:
#             raise Http404(PublicKeyInfoMissingErrorMsg)

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
#             return f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
#             if not device.public_key_info.named_curve:
#                 raise Http404(NamedCurveMissingForEccErrorMsg)
#             return (
#                 f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
#                 f'-genkey -noout -out domain_credential_key.pem'
#             )

#         err_msg = _('Unsupported public key algorithm')
#         raise ValueError(err_msg)

#     def _get_tls_server_cert(self) -> str:
#         tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
#         if not tls_cert or not tls_cert.credential:
#             raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
#         return tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8')

#     # @staticmethod
#     # def _get_domain_credential_cmp_context(device: DeviceModel) -> dict[str, Any]:
#     #     """Provides the context for cmp commands using client based authentication.

#     #     Args:
#     #         device: The corresponding device model.

#     #     Returns:
#     #         The required context.
#     #     """
#     #     if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
#     #         domain_credential_key_gen_command = (
#     #             f'openssl genrsa -out domain_credential_key.pem {device.public_key_info.key_size}'
#     #         )
#     #         key_gen_command = f'openssl genrsa -out key.pem {device.public_key_info.key_size}'
#     #     elif device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
#     #         if not device.public_key_info.named_curve:
#     #             raise Http404(NamedCurveMissingForEccErrorMsg)
#     #         domain_credential_key_gen_command = (
#     #             f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
#     #             f'-genkey -noout -out domain_credential_key.pem'
#     #         )
#     #         key_gen_command = (
#     #             f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
#     #             f'-genkey -noout -out key.pem'
#     #         )
#     #     else:
#     #         err_msg = _('Unsupported public key algorithm')
#     #         raise ValueError(err_msg)

#     #     if not device.onboarding_config:
#     #         err_msg = _('Device is not configured for onboarding.')
#     #         raise Http404(err_msg)
#     #     context['cmp_shared_secret'] = device.onboarding_config.onboarding_cmp_shared_secret
#     #     context['domain_credential_key_gen_command'] = domain_credential_key_gen_command
#     #     context['key_gen_command'] = key_gen_command
#     #     context['issuing_ca_pem'] = (
#     #         device.domain.get_issuing_ca_or_value_error().credential.get_certificate()
#     #         .public_bytes(encoding=serialization.Encoding.PEM)
#     #         .decode()
#     #     )
#     #     return context

# class DeviceOnboardingCmpSharedSecretHelpView(AbstractCredentialIssuanceHelpView):
#     """Help view for the onboarding cmp-shared secret case."""

#     template_name = 'help/onboarding/cmp_shared_secret.html'

#     page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
#     pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET


# class OpcUaGdsOnboardingCmpSharedSecretHelpView(AbstractCredentialIssuanceHelpView):
#     """Help view for the onboarding cmp-shared secret case."""

#     template_name = 'help/onboarding/cmp_shared_secret.html'

#     page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
#     pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET


# class AbstractNoOnboardingHelpView(PageContextMixin, DetailView[DeviceModel]):
#     """Base view for CMP help views concerning the domain credential, not intended to be used directly."""

#     http_method_names = ('get',)

#     model = DeviceModel
#     template_name: str
#     context_object_name = 'device'

#     page_category = DEVICES_PAGE_CATEGORY
#     page_name: str

#     pki_protocol: NoOnboardingPkiProtocol

#     no_onboarding_config: NoOnboardingConfigModel

#     def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
#         """Adds information about the required OpenSSL commands to the context.

#         Args:
#             **kwargs: Keyword arguments passed to super().get_context_data.

#         Returns:
#             The context to render the page.
#         """
#         print('hello')
#         context = super().get_context_data(**kwargs)
#         device: DeviceModel = self.object
#         if not device.no_onboarding_config:
#             err_msg = _('Onboarding is configured for this device.')
#             raise Http404(err_msg)
#         self.no_onboarding_config = device.no_onboarding_config

#         certificate_profile = self.kwargs.get('certificate_template')
#         if not certificate_profile:
#             err_msg = _('Failed to get certificate profile')
#         number_of_issued_device_certificates = len(IssuedCredentialModel.objects.filter(device=device))
#         camelcase_profile = ''.join(word.capitalize() for word in certificate_profile.split('-'))
#         context['cn_entry'] = f'Trustpoint-{camelcase_profile}-Credential-{number_of_issued_device_certificates}'

#         context['certificate_profile'] = certificate_profile

#         ipv4_address = TlsSettings.get_first_ipv4_address()
#         context['host'] = f'{ipv4_address}:{self.request.META.get("SERVER_PORT", "443")}'
#         context['domain'] = device.domain

#         context['key_gen_command'] = self._get_key_gen_command()

#         # context['trustpoint_server_certificate'] = self._get_tls_server_cert()
#         context['shared_secret'] = self._get_shared_secret()
#         context['cmp_tls_client_command'] = self._get_cert_request_command()

#         context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

#         return context

#     def _get_key_gen_command(self) -> str:
#         device: DeviceModel = self.object
#         if device.domain is None:
#             raise Http404(DeviceWithoutDomainErrorMsg)

#         if not device.public_key_info:
#             raise Http404(PublicKeyInfoMissingErrorMsg)

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.RSA:
#             return f'openssl genrsa -out key.pem {device.public_key_info.key_size}'

#         if device.public_key_info.public_key_algorithm_oid == oid.PublicKeyAlgorithmOid.ECC:
#             if not device.public_key_info.named_curve:
#                 raise Http404(NamedCurveMissingForEccErrorMsg)
#             return (
#                 f'openssl ecparam -name {device.public_key_info.named_curve.ossl_curve_name} '
#                 f'-genkey -noout -out key.pem'
#             )

#         err_msg = _('Unsupported public key algorithm')
#         raise ValueError(err_msg)

#     def _get_cert_request_command(self) -> str | SafeString:
#         if self.pki_protocol == NoOnboardingPkiProtocol.CMP_SHARED_SECRET:
#             return self._get_cmp_cert_request_command()
#         return self._get_est_cert_request_command()

#     def _get_cmp_cert_request_command(self) -> SafeString:
#         return format_html(
#             'openssl cmp \\<br>'
#             '-cmd cr \\<br>'
#             '-implicit_confirm \\<br>'
#             '-server https://{{ host }}/.well-known/cmp/certification/{{ device.domain }}/tls-client/ \\<br>'
#             '-tls_used \\<br>'
#             '-ref {{ device.id }} \\<br>'
#             '-secret pass:{{ cmp_shared_secret }} \\<br>'
#             '-subject "/CN={{ cn_entry }}" \\<br>'
#             '-days 10 \\<br>'
#             '-newkey key.pem \\<br>'
#             '-certout cert.pem \\<br>'
#             '-chainout chain_without_root.pem \\<br>'
#             '-extracertsout full_chain.pem'
#         )

#     def _get_est_cert_request_command(self) -> str:
#         return ''

#     def _get_tls_server_cert(self) -> str:
#         tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
#         if not tls_cert or not tls_cert.credential:
#             raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
#         return tls_cert.credential.certificate.get_certificate_serializer().as_pem().decode('utf-8')

#     def _get_shared_secret(self) -> str:
#         if self.pki_protocol == NoOnboardingPkiProtocol.CMP_SHARED_SECRET:
#             return self.no_onboarding_config.cmp_shared_secret
#         return self.no_onboarding_config.est_username_password


# # class DeviceNoOnboardingCmpSharedSecretHelpView(AbstractNoOnboardingHelpView):
# #     """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

# #     template_name = 'help/no_onboarding/cmp_shared_secret.html'

# #     page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
# #     pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET


# class DeviceNoOnboardingEstUsernamePasswordHelpView(AbstractNoOnboardingHelpView):
#     """View to provide help information for EST username/password authentication with no onboarding."""

#     template_name = 'help/deprecated/no_onboarding/est_username_password.html'

#     page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
#     pki_protocol = NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD

# class OpcUaGdsNoOnboardingEstUsernamePasswordHelpView(AbstractNoOnboardingHelpView):
#     """View to provide help information for EST username/password authentication with no onboarding and OPC UA GDS."""

#     template_name = 'help/deprecated/no_onboarding/est_gds_username_password.html'

#     page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
#     pki_protocol = NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD



