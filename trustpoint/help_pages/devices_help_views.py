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
    OnboardingConfigModel,
    OnboardingProtocol,
)
from devices.views import (
    ActiveTrustpointTlsServerCredentialModelMissingErrorMsg,
    DeviceWithoutDomainErrorMsg,
    PublicKeyInfoMissingErrorMsg,
)
from django.http import Http404
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext as _non_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
from management.models import TlsSettings
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel

from help_pages.commands import (
    CmpClientCertificateCommandBuilder,
    CmpSharedSecretCommandBuilder,
    EstClientCertificateCommandBuilder,
    EstUsernamePasswordCommandBuilder,
    KeyGenCommandBuilder,
)
from help_pages.help_section import HelpPage, HelpRow, HelpSection, ValueRenderType
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)

if TYPE_CHECKING:
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
    operation: str

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
        # @TODO: When device is onboarded on multiple domains make sure to select the correct domain
        self.domain = self.object.domain
        self.certificate_profile = self.kwargs.get('certificate_template')
        if not self.certificate_profile:
            err_msg = _('Failed to get certificate profile')
        self.operation = 'certification'
        self.host = (
            f'{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}/'
            f'.well-known/cmp/p/{self.domain.unique_name}'
        )

        help_page = HelpPage(
            heading=_non_lazy('Help - CMP Shared-Secret (HMAC)'),
            sections=[
                self._get_summary_section(),
                self._get_key_generation_section(),
                self._get_certificate_profile_select_section(),
                self._get_cmp_tls_client_profile_cmd_section(),
                self._get_cmp_tls_server_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_client_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_server_profile_cmd_section(hidden=True),
            ],
        )

        context['help_page'] = help_page

        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_certificate_profile_select_section(self) -> HelpSection:
        cert_profile_select_row = HelpRow(
            key=_non_lazy('Certificate Profile'),
            value=self._get_cert_profile_select_input(),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Certificate Profile Selection'), rows=[cert_profile_select_row])

    def _get_cmp_tls_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_tls_client_profile_command(
            host=self.host + '/tls-client/' + self.operation,
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
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
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name,
        )

    def _get_cmp_tls_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_tls_server_profile_command(
            host=self.host + '/tls-server/' + self.operation,
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        openssl_cmd_tls_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'), value=cmp_command, value_render_type=ValueRenderType.CODE, hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for TLS Server Certificates'),
            rows=[openssl_cmd_tls_server_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_SERVER.name,
        )

    def _get_cmp_opc_ua_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_opc_ua_client_profile_command(
            host=self.host + '/opc-ua-client/' + self.operation,
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        openssl_cmd_opc_ua_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'), value=cmp_command, value_render_type=ValueRenderType.CODE, hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for OPC-UA Client Certificates'),
            rows=[openssl_cmd_opc_ua_client_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.name,
        )

    def _get_cmp_opc_ua_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_opc_ua_server_profile_command(
            host=self.host + '/opc-ua-server/' + self.operation,
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        openssl_cmd_opc_ua_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'), value=cmp_command, value_render_type=ValueRenderType.CODE, hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for OPC-UA Server Certificates'),
            rows=[openssl_cmd_opc_ua_server_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.name,
        )

    def _get_summary_section(self) -> HelpSection:
        if self.domain is None:
            raise ValueError
        certificate_request_url = f'https://{self.host}/<certificate_profile>/{self.operation}'
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE,
        )
        kid_row = HelpRow(
            key=_non_lazy('Key Identifier (KID)'), value=str(self.object.pk), value_render_type=ValueRenderType.CODE
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.domain.public_key_info),
            value_render_type=ValueRenderType.CODE,
        )
        shared_secret_row = HelpRow(
            key=('Shared-Secret'),
            value=self._get_shared_secret(),
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Summary'), rows=[url_row, kid_row, public_key_type_row, shared_secret_row]
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
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=format_html(_non_lazy('Key Generation')), rows=[key_generation_row])

    def _get_key_gen_command(self) -> str:
        if self.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not self.domain.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=self.domain.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
            )
        except Exception as exception:
            raise Http404(exception) from exception

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

        if not self.domain:
            err_msg = _('No domain is configured for this device.')
            raise Http404(err_msg)
        # @TODO: When device is onboarded on multiple domains make sure to select the correct domain
        self.domain = self.domain
        self.certificate_profile = self.kwargs.get('certificate_template')
        if not self.certificate_profile:
            err_msg = _('Failed to get certificate profile')
        self.host = f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}'

        help_page = HelpPage(
            heading=_non_lazy('Help - EST Username & Password'),
            sections=[
                self._get_summary_section(),
                self._get_download_tls_trust_store_section(),
                self._get_key_generation_section(),
                self._get_certificate_profile_select_section(),
                self._get_cmp_tls_client_profile_cmd_section(),
                self._get_cmp_tls_server_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_client_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_server_profile_cmd_section(hidden=True),
                self._get_conversion_der_to_pem_section(),
            ],
        )

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
            key=_non_lazy('OpenSSL Command'), value=conversion_cmd, value_render_type=ValueRenderType.CODE
        )
        return HelpSection(
            heading='Convert the certificate from DER format to PEM format (Optional)', rows=[conversion_row]
        )

    def _get_certificate_profile_select_section(self) -> HelpSection:
        cert_profile_select_row = HelpRow(
            key=_non_lazy('Certificate Profile'),
            value=self._get_cert_profile_select_input(),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Certificate Profile Selection'), rows=[cert_profile_select_row])

    def _get_enroll_row(self, certificate_profile: str) -> HelpRow:
        enroll_cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_command(
            est_username=self.object.common_name,
            est_password=self.no_onboarding_config.est_password,
            host=f'{self.host}/.well-known/est/{self.domain.unique_name}/{certificate_profile}/simpleenroll/',
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        return HelpRow(
            key=_non_lazy('Enroll certificate with curl'), value=enroll_cmd, value_render_type=ValueRenderType.CODE
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
            rows=[openssl_req_cmd_tls_client_profile_row, self._get_enroll_row(certificate_profile='tls-client')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name,
        )

    def _get_cmp_tls_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_tls_server_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_tls_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False,
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for TLS Server Certificates'),
            rows=[openssl_req_cmd_tls_server_profile_row, self._get_enroll_row(certificate_profile='tls-server')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_SERVER.name,
        )

    def _get_cmp_opc_ua_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_client_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_opc_ua_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False,
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for OPC-UA Client Certificates'),
            rows=[openssl_req_cmd_opc_ua_client_profile_row, self._get_enroll_row(certificate_profile='opc-ua-client')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.name,
        )

    def _get_cmp_opc_ua_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_server_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_opc_ua_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False,
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for OPC-UA Server Certificates'),
            rows=[openssl_req_cmd_opc_ua_server_profile_row, self._get_enroll_row(certificate_profile='opc-ua-server')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.name,
        )

    def _get_summary_section(self) -> HelpSection:
        if self.domain is None:
            raise ValueError
        certificate_request_url = (
            f'https://{self.host}/.well-known/est/{self.domain.unique_name}/<certificate_profile>/simpleenroll/'
        )
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE,
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.domain.public_key_info),
            value_render_type=ValueRenderType.CODE,
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
            key=('EST-Password'),
            value=self.object.no_onboarding_config.est_password,
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Summary'), rows=[url_row, public_key_type_row, est_username_row, est_password]
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
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=format_html(_non_lazy('Key Generation')), rows=[key_generation_row])

    def _get_key_gen_command(self) -> str:
        if self.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not self.domain.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=self.domain.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
            )
        except Exception as exception:
            raise Http404(exception) from exception

    def _get_shared_secret(self) -> str:
        return self.no_onboarding_config.cmp_shared_secret

    def _get_download_tls_trust_store_section(self) -> HelpSection:
        tls_cert_pk = self._get_tls_server_root_ca_pk()
        if tls_cert_pk is None:
            err_msg = _non_lazy('Failed to get the Trustpoint TLS Root Certificate.')
            raise ValueError(err_msg)

        download_tls_truststore_row = HelpRow(
            key=_non_lazy('Download TLS Trust-Store'),
            value=format_html(
                '<a href="{}" class="btn btn-primary w-100">{}</a>',
                reverse(
                    'pki:certificate-file-download-file-name',
                    kwargs={'file_format': 'pem', 'pk': tls_cert_pk, 'file_name': 'trustpoint-tls-trust-store.pem'},
                ),
                _non_lazy('Download TLS Trust-Store'),
            ),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Download TLS Trust-Store'), rows=[download_tls_truststore_row])

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


class AbstractOnboardingDomainCredentialCmpSharedSecretHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Abstract help view for the case of no onboarding using CMP shared-secret."""

    template_name = 'help/help_page.html'

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    onboarding_protocol = OnboardingProtocol.CMP_SHARED_SECRET

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    onboarding_config: OnboardingConfigModel
    domain: DomainModel

    host: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        if not self.object.onboarding_config:
            err_msg = _('Onboarding is not configured for this device.')
            raise Http404(err_msg)
        self.onboarding_config = self.object.onboarding_config

        if not self.domain:
            err_msg = _('No domain is configured for this device.')
            raise Http404(err_msg)
        # @TODO: When device is onboarded on multiple domains make sure to select the correct domain
        self.domain = self.domain

        self.host = f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}'

        help_page = HelpPage(
            heading=_non_lazy('Help - CMP Shared-Secret (HMAC)'),
            sections=[
                self._get_summary_section(),
                self._get_key_generation_section(),
                self._get_cmp_domain_credential_cmd_section(),
            ],
        )

        context['help_page'] = help_page

        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_certificate_profile_select_section(self) -> HelpSection:
        cert_profile_select_row = HelpRow(
            key=_non_lazy('Certificate Profile'),
            value=self._get_cert_profile_select_input(),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Certificate Profile Selection'), rows=[cert_profile_select_row])

    def _get_cmp_domain_credential_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpSharedSecretCommandBuilder.get_domain_credential_profile_command(
            host=self.host,
            pk=self.object.pk,
            shared_secret=self._get_shared_secret(),
            domain_name=self.domain.unique_name,
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
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name,
        )

    def _get_summary_section(self) -> HelpSection:
        if self.domain is None:
            raise ValueError
        certificate_request_url = f'{self.host}/.well-known/cmp/{self.domain.unique_name}/initialization'
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE,
        )
        kid_row = HelpRow(
            key=_non_lazy('Key Identifier (KID)'), value=str(self.object.pk), value_render_type=ValueRenderType.CODE
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.domain.public_key_info),
            value_render_type=ValueRenderType.CODE,
        )
        shared_secret_row = HelpRow(
            key=('Shared-Secret'),
            value=self._get_shared_secret(),
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Summary'), rows=[url_row, kid_row, public_key_type_row, shared_secret_row]
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
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=format_html(_non_lazy('Key Generation')), rows=[key_generation_row])

    def _get_key_gen_command(self) -> str:
        if self.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not self.domain.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=self.domain.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
                key_name='domain-credential-key.pem',
            )
        except Exception as exception:
            raise Http404(exception) from exception

    def _get_shared_secret(self) -> str:
        return self.onboarding_config.cmp_shared_secret


class DeviceOnboardingDomainCredentialCmpSharedSecretHelpView(
    AbstractOnboardingDomainCredentialCmpSharedSecretHelpView
):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingDomainCredentialCmpSharedSecretHelpView(
    AbstractOnboardingDomainCredentialCmpSharedSecretHelpView
):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractOnboardingDomainCredentialEstUsernamePasswordHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Abstract help view for the case of no onboarding using CMP shared-secret."""

    template_name = 'help/help_page.html'

    pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    onboarding_config: OnboardingConfigModel
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
        if not self.object.onboarding_config:
            err_msg = _('Onboarding is not configured for this device.')
            raise Http404(err_msg)
        self.onboarding_config = self.object.onboarding_config

        if not self.domain:
            err_msg = _('No domain is configured for this device.')
            raise Http404(err_msg)
        # @TODO: When device is onboarded on multiple domains make sure to select the correct domain
        self.domain = self.domain
        self.certificate_profile = 'domaincredential'
        if not self.certificate_profile:
            err_msg = _('Failed to get certificate profile')
        self.host = f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}'

        help_page = HelpPage(
            heading=_non_lazy('Help - EST Username & Password'),
            sections=[
                self._get_summary_section(),
                self._get_download_tls_trust_store_section(),
                self._get_key_generation_section(),
                self._get_est_domain_cred_profile_cmd_section(),
                self._get_conversion_der_to_pem_section(),
            ],
        )

        context['help_page'] = help_page

        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_conversion_der_to_pem_section(self) -> HelpSection:
        conversion_cmd = EstUsernamePasswordCommandBuilder.get_domain_credential_conversion_der_pem_command()
        conversion_row = HelpRow(
            key=_non_lazy('OpenSSL Command'), value=conversion_cmd, value_render_type=ValueRenderType.CODE
        )
        return HelpSection(
            heading='Convert the certificate from DER format to PEM format (Optional)', rows=[conversion_row]
        )

    def _get_enroll_row(self, certificate_profile: str) -> HelpRow:
        enroll_cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_domain_credential_command(
            est_username=self.object.common_name,
            est_password=self.onboarding_config.est_password,
            host=f'{self.host}/.well-known/est/{self.domain.unique_name}/{certificate_profile}/simpleenroll/',
        )
        return HelpRow(
            key=_non_lazy('Enroll certificate with curl'), value=enroll_cmd, value_render_type=ValueRenderType.CODE
        )

    def _get_est_domain_cred_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_domain_credential_profile_command()
        openssl_req_cmd_tls_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for the domain credential'),
            rows=[
                openssl_req_cmd_tls_client_profile_row,
                self._get_enroll_row(certificate_profile=self.certificate_profile),
            ],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name,
        )

    def _get_summary_section(self) -> HelpSection:
        if self.domain is None:
            raise ValueError
        certificate_request_url = (
            f'https://{self.host}/.well-known/est/{self.domain.unique_name}/<certificate_profile>/simpleenroll/'
        )
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE,
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.domain.public_key_info),
            value_render_type=ValueRenderType.CODE,
        )
        est_username_row = HelpRow(
            key=('EST-Username'),
            value=self.object.common_name,
            value_render_type=ValueRenderType.CODE,
        )
        if not self.object.onboarding_config:
            err_msg = 'Device not configured for onboarding.'
            raise ValueError(err_msg)
        est_password = HelpRow(
            key=('EST-PasswordU'),
            value=self.object.onboarding_config.est_password,
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(
            heading=_non_lazy('Summary'), rows=[url_row, public_key_type_row, est_username_row, est_password]
        )

    def _get_key_generation_section(self) -> HelpSection:
        key_generation_row = HelpRow(
            key=_non_lazy('Generate Key-Pair'),
            value=self._get_key_gen_command(),
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=format_html(_non_lazy('Key Generation')), rows=[key_generation_row])

    def _get_key_gen_command(self) -> str:
        if self.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not self.domain.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=self.domain.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
                key_name='domain-credential-key.pem',
            )
        except Exception as exception:
            raise Http404(exception) from exception

    def _get_download_tls_trust_store_section(self) -> HelpSection:
        tls_cert_pk = self._get_tls_server_root_ca_pk()
        if tls_cert_pk is None:
            err_msg = _non_lazy('Failed to get the Trustpoint TLS Root Certificate.')
            raise ValueError(err_msg)

        download_tls_truststore_row = HelpRow(
            key=_non_lazy('Download TLS Trust-Store'),
            value=format_html(
                '<a href="{}" class="btn btn-primary w-100">{}</a>',
                reverse(
                    'pki:certificate-file-download-file-name',
                    kwargs={'file_format': 'pem', 'pk': tls_cert_pk, 'file_name': 'trustpoint-tls-trust-store.pem'},
                ),
                _non_lazy('Download TLS Trust-Store'),
            ),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Download TLS Trust-Store'), rows=[download_tls_truststore_row])

    def _get_tls_server_root_ca_pk(self) -> None | int:
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert or not tls_cert.credential:
            raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
        root_ca_model = tls_cert.credential.get_last_in_chain()
        if not root_ca_model:
            return None
        return root_ca_model.pk


class DeviceOnboardingDomainCredentialEstUsernamePasswordHelpView(
    AbstractOnboardingDomainCredentialEstUsernamePasswordHelpView
):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingDomainCredentialEstUsernamePasswordHelpView(
    AbstractOnboardingDomainCredentialEstUsernamePasswordHelpView
):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractOnboardingCmpDomainCredentialHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Abstract help view for the case of onboarding using CMP shared-secret."""

    template_name = 'help/help_page.html'

    pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    onboarding_config: OnboardingConfigModel

    certificate_profile: str
    host: str
    operation: str

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the required OpenSSL commands to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        if not self.object.onboarding_config:
            err_msg = _('Onboarding is not configured for this device.')
            raise Http404(err_msg)
        self.onboarding_config = self.object.onboarding_config

        if not self.object.domain:
            err_msg = _('No domain is configured for this device.')
            raise Http404(err_msg)
        # @TODO: When device is onboarded on multiple domains make sure to select the correct domain
        self.domain = self.object.domain
        self.operation = 'certification'
        self.host = (
            f'{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}/'
            f'.well-known/cmp/p/{self.domain.unique_name}'
        )

        help_page = HelpPage(
            heading=_non_lazy('Help - CMP Shared-Secret (HMAC)'),
            sections=[
                self._get_summary_section(),
                self._get_download_cmp_signer_trust_store_section(),
                self._get_key_generation_section(),
                self._get_certificate_profile_select_section(),
                self._get_cmp_tls_client_profile_cmd_section(),
                self._get_cmp_tls_server_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_client_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_server_profile_cmd_section(hidden=True),
            ],
        )

        context['help_page'] = help_page

        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value

        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'

        return context

    def _get_certificate_profile_select_section(self) -> HelpSection:
        cert_profile_select_row = HelpRow(
            key=_non_lazy('Certificate Profile'),
            value=self._get_cert_profile_select_input(),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Certificate Profile Selection'), rows=[cert_profile_select_row])

    def _get_cmp_tls_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpClientCertificateCommandBuilder.get_tls_client_profile_command(
            host=self.host + '/tls-client/' + self.operation,
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
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
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name,
        )

    def _get_cmp_tls_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpClientCertificateCommandBuilder.get_tls_server_profile_command(
            host=self.host + '/tls-server/' + self.operation,
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        openssl_cmd_tls_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'), value=cmp_command, value_render_type=ValueRenderType.CODE, hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for TLS Server Certificates'),
            rows=[openssl_cmd_tls_server_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_SERVER.name,
        )

    def _get_cmp_opc_ua_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpClientCertificateCommandBuilder.get_opc_ua_client_profile_command(
            host=self.host + '/opc-ua-client/' + self.operation,
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        openssl_cmd_opc_ua_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'), value=cmp_command, value_render_type=ValueRenderType.CODE, hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for OPC-UA Client Certificates'),
            rows=[openssl_cmd_opc_ua_client_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.name,
        )

    def _get_cmp_opc_ua_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        cmp_command = CmpClientCertificateCommandBuilder.get_opc_ua_server_profile_command(
            host=self.host + '/opc-ua-server/' + self.operation,
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        openssl_cmd_opc_ua_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'), value=cmp_command, value_render_type=ValueRenderType.CODE, hidden=False
        )
        return HelpSection(
            heading=_non_lazy('Certificate Request for OPC-UA Server Certificates'),
            rows=[openssl_cmd_opc_ua_server_profile_row],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.name,
        )

    def _get_summary_section(self) -> HelpSection:
        if self.object is None:
            raise ValueError
        certificate_request_url = self.host + '/<certificate_profile>/' + self.operation
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE,
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.domain.public_key_info),
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=_non_lazy('Summary'), rows=[url_row, public_key_type_row])

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
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=format_html(_non_lazy('Key Generation')), rows=[key_generation_row])

    def _get_key_gen_command(self) -> str:
        device: DeviceModel = self.object
        if device.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not self.domain.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=self.domain.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
            )
        except Exception as exception:
            raise Http404(exception) from exception

    def _get_cmp_issuer_root_ca_pk(self) -> None | int:
        domain = self.domain
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

    def _get_download_cmp_signer_trust_store_section(self) -> HelpSection:
        cmp_signer_pk = self._get_cmp_issuer_root_ca_pk()
        if cmp_signer_pk is None:
            err_msg = _non_lazy('Failed to get the CMP-Signer Root Certificate.')
            raise ValueError(err_msg)

        download_tls_truststore_row = HelpRow(
            key=_non_lazy('Download CMP-Signer Trust-Store'),
            value=format_html(
                '<a href="{}" class="btn btn-primary w-100">{}</a>',
                reverse(
                    'pki:certificate-file-download-file-name',
                    kwargs={'file_format': 'pem', 'pk': cmp_signer_pk, 'file_name': 'domain-credential-full-chain.pem'},
                ),
                _non_lazy('Download CMP-Signer Trust-Store'),
            ),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Download CMP-Signer Trust-Store'), rows=[download_tls_truststore_row])


class DeviceOnboardingCmpDomainCredentialHelpView(AbstractOnboardingCmpDomainCredentialHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingCmpDomainCredentialHelpView(AbstractOnboardingCmpDomainCredentialHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic devices."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY


class AbstractDeviceOnboardingEstDomainCredentialHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Abstract help view for the case of no onboarding using CMP shared-secret."""

    template_name = 'help/help_page.html'

    pki_protocol = NoOnboardingPkiProtocol.CMP_SHARED_SECRET

    http_method_names = ('get',)

    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str

    onboarding_config: OnboardingConfigModel
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
        if not self.object.onboarding_config:
            err_msg = _('Onboarding is not configured for this device.')
            raise Http404(err_msg)
        self.onboarding_config = self.object.onboarding_config

        if not self.domain:
            err_msg = _('No domain is configured for this device.')
            raise Http404(err_msg)
        # @TODO: When device is onboarded on multiple domains make sure to select the correct domain
        self.domain = self.domain
        self.certificate_profile = self.kwargs.get('certificate_template')
        if not self.certificate_profile:
            err_msg = _('Failed to get certificate profile')
        self.host = f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}'

        help_page = HelpPage(
            heading=_non_lazy('Help - EST with Domain Credential'),
            sections=[
                self._get_summary_section(),
                self._get_download_tls_trust_store_section(),
                self._get_key_generation_section(),
                self._get_certificate_profile_select_section(),
                self._get_cmp_tls_client_profile_cmd_section(),
                self._get_cmp_tls_server_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_client_profile_cmd_section(hidden=True),
                self._get_cmp_opc_ua_server_profile_cmd_section(hidden=True),
                self._get_conversion_der_to_pem_section(),
            ],
        )

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
            key=_non_lazy('OpenSSL Command'), value=conversion_cmd, value_render_type=ValueRenderType.CODE
        )
        return HelpSection(
            heading='Convert the certificate from DER format to PEM format (Optional)', rows=[conversion_row]
        )

    def _get_certificate_profile_select_section(self) -> HelpSection:
        cert_profile_select_row = HelpRow(
            key=_non_lazy('Certificate Profile'),
            value=self._get_cert_profile_select_input(),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Certificate Profile Selection'), rows=[cert_profile_select_row])

    def _get_enroll_row(self, certificate_profile: str) -> HelpRow:
        enroll_cmd = EstClientCertificateCommandBuilder.get_curl_enroll_application_credential(
            host=f'{self.host}/.well-known/est/{self.domain.unique_name}/{certificate_profile}/simpleenroll/',
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
        )
        return HelpRow(
            key=_non_lazy('Enroll certificate with curl'), value=enroll_cmd, value_render_type=ValueRenderType.CODE
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
            rows=[openssl_req_cmd_tls_client_profile_row, self._get_enroll_row(certificate_profile='tls-client')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_CLIENT.name,
        )

    def _get_cmp_tls_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_tls_server_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_tls_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False,
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for TLS Server Certificates'),
            rows=[openssl_req_cmd_tls_server_profile_row, self._get_enroll_row(certificate_profile='tls-server')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.TLS_SERVER.name,
        )

    def _get_cmp_opc_ua_client_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_client_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_opc_ua_client_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False,
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for OPC-UA Client Certificates'),
            rows=[openssl_req_cmd_opc_ua_client_profile_row, self._get_enroll_row(certificate_profile='opc-ua-client')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.name,
        )

    def _get_cmp_opc_ua_server_profile_cmd_section(self, *, hidden: bool = False) -> HelpSection:
        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_server_profile_command(
            cred_number=len(IssuedCredentialModel.objects.filter(device=self.object))
        )
        openssl_req_cmd_opc_ua_server_profile_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
            hidden=False,
        )
        return HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for OPC-UA Server Certificates'),
            rows=[openssl_req_cmd_opc_ua_server_profile_row, self._get_enroll_row(certificate_profile='opc-ua-server')],
            hidden=hidden,
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.name,
        )

    def _get_summary_section(self) -> HelpSection:
        if self.domain is None:
            raise ValueError
        certificate_request_url = (
            f'https://{self.host}/.well-known/est/{self.domain.unique_name}/<certificate_profile>/simpleenroll/'
        )
        url_row = HelpRow(
            key=format_html(_non_lazy('Certificate Request URL')),
            value=certificate_request_url,
            value_render_type=ValueRenderType.CODE,
        )
        public_key_type_row = HelpRow(
            key=_non_lazy('Required Public Key Type'),
            value=str(self.domain.public_key_info),
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=_non_lazy('Summary'), rows=[url_row, public_key_type_row])

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
            value_render_type=ValueRenderType.CODE,
        )

        return HelpSection(heading=format_html(_non_lazy('Key Generation')), rows=[key_generation_row])

    def _get_key_gen_command(self) -> str:
        if self.domain is None:
            raise Http404(DeviceWithoutDomainErrorMsg)

        if not self.domain.public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)
        try:
            return KeyGenCommandBuilder.get_key_gen_command(
                public_key_info=self.domain.public_key_info,
                cred_number=len(IssuedCredentialModel.objects.filter(device=self.object)),
            )
        except Exception as exception:
            raise Http404(exception) from exception

    def _get_download_tls_trust_store_section(self) -> HelpSection:
        tls_cert_pk = self._get_tls_server_root_ca_pk()
        if tls_cert_pk is None:
            err_msg = _non_lazy('Failed to get the Trustpoint TLS Root Certificate.')
            raise ValueError(err_msg)

        download_tls_truststore_row = HelpRow(
            key=_non_lazy('Download TLS Trust-Store'),
            value=format_html(
                '<a href="{}" class="btn btn-primary w-100">{}</a>',
                reverse(
                    'pki:certificate-file-download-file-name',
                    kwargs={'file_format': 'pem', 'pk': tls_cert_pk, 'file_name': 'trustpoint-tls-trust-store.pem'},
                ),
                _non_lazy('Download TLS Trust-Store'),
            ),
            value_render_type=ValueRenderType.PLAIN,
        )

        return HelpSection(heading=_non_lazy('Download TLS Trust-Store'), rows=[download_tls_truststore_row])

    def _get_tls_server_root_ca_pk(self) -> None | int:
        tls_cert = ActiveTrustpointTlsServerCredentialModel.objects.first()
        if not tls_cert or not tls_cert.credential:
            raise Http404(ActiveTrustpointTlsServerCredentialModelMissingErrorMsg)
        root_ca_model = tls_cert.credential.get_last_in_chain()
        if not root_ca_model:
            return None
        return root_ca_model.pk


class DeviceOnboardingEstDomainCredentialHelpView(AbstractDeviceOnboardingEstDomainCredentialHelpView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY


class OpcUaGdsOnboardingEstDomainCredentialHelpView(AbstractDeviceOnboardingEstDomainCredentialHelpView):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
