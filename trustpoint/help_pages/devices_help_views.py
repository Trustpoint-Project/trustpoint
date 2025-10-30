"""This module contains all views concerning the help pages used within the devices app."""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, override

from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
)
from devices.views import (
    ActiveTrustpointTlsServerCredentialModelMissingErrorMsg,
    DeviceWithoutDomainErrorMsg,
    PublicKeyInfoMissingErrorMsg,
)
from django.http import Http404
from django.urls import reverse
from django.utils.html import format_html, format_html_join
from django.utils.translation import gettext as _non_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
from management.models import TlsSettings
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)

from help_pages.commands import (
    CmpClientCertificateCommandBuilder,
    CmpSharedSecretCommandBuilder,
    EstClientCertificateCommandBuilder,
    EstUsernamePasswordCommandBuilder,
    KeyGenCommandBuilder,
)
from help_pages.help_section import HelpPage, HelpRow, HelpSection, ValueRenderType

if TYPE_CHECKING:
    from typing import Any, Self

    from django.utils.safestring import SafeString
    from pki.models.domain import DomainModel
    from trustpoint_core import oid


# ----------------------------------------- Application Certificate Profiles ------------------------------------------


@dataclass(frozen=True)
class ApplicationCertificateProfileData:
    """The application certificate profile data class that holds both profile_name and profile_label."""

    profile_name: str
    profile_label: str


class ApplicationCertificateProfile(enum.Enum):
    """Allowed application credential profiles."""

    TLS_CLIENT = ApplicationCertificateProfileData('tls-client', 'TLS-Client Certificate')
    TLS_SERVER = ApplicationCertificateProfileData('tls-server', 'TLS-Server Certificate')
    OPC_UA_CLIENT = ApplicationCertificateProfileData('opc-ua-client', 'OPC-UA-Client Certificate')
    OPC_UA_SERVER = ApplicationCertificateProfileData('opc-ua-server', 'OPC-UA-Server Certificate')

    @property
    def profile_name(self) -> str:
        """Return the name of the profile.

        Returns:
            The name of the profile.
        """
        return self.value.profile_name

    @property
    def profile_label(self) -> str:
        """Return the label of the profile.

        Returns:
            The label of the profile.
        """
        return self.value.profile_label

    @classmethod
    def from_profile_name(cls, profile_name: str) -> Self:
        """Gets the ApplicationCertificateProfile matching the name.

        Returns:
            The matching ApplicationCertificateProfile.

        Raises:
            ValueError: If no matching ApplicationCertificateProfile is found for the profile name provided.
        """
        for member in cls:
            if member.value.profile_name == profile_name:
                return member
        err_msg = f'No ApplicationCertificateProfile with profile_name={profile_name} found.'
        raise ValueError(err_msg)

    @classmethod
    def from_label(cls, profile_label: str) -> Self:
        """Gets the ApplicationCertificateProfile matching the label.

        Returns:
            The matching ApplicationCertificateProfile.

        Raises:
            ValueError: If no matching ApplicationCertificateProfile is found for the label provided.
        """
        for member in cls:
            if member.value.profile_label == profile_label:
                return member
        err_msg = f'No ApplicationCertificateProfile with profile_label={profile_label} found.'
        raise ValueError(err_msg)

    def __str__(self) -> str:
        """Gets the profile_label as human-readable string.

        Returns:
            The profile_label.
        """
        return self.profile_label


# ----------------------------------------- Reusable section build functions ------------------------------------------


def build_keygen_section(help_context: HelpContext, file_name: str) -> HelpSection:
    """Builds the key-generation section.

    Args:
        help_context: The help context which will
        file_name: The file_name to use if the default shall not be used. Defaults to None.

    Returns:
        The key-generation section.
    """
    cmd = KeyGenCommandBuilder.get_key_gen_command(
        public_key_info=help_context.public_key_info, cred_number=help_context.cred_count, key_name=file_name
    )
    return HelpSection(
        _non_lazy('Key Generation'), [HelpRow(_non_lazy('Generate Key-Pair'), cmd, ValueRenderType.CODE)]
    )


def build_profile_select_section(app_cert_profiles: list[ApplicationCertificateProfile]) -> HelpSection:
    """Builds the profile select section.

    Returns:
        The profile select section.
    """
    options = format_html_join(
        '',
        '<option value="{}"{}>{}</option>',
        (
            (
                p.profile_name,
                ' selected' if i == 0 else '',
                p.profile_label,
            )
            for i, p in enumerate(app_cert_profiles)
        ),
    )
    select = format_html(
        '<select id="cert-profile-select" class="form-select" aria-label="Certificate Profile Select">{}</select>',
        options,
    )
    return HelpSection(
        _non_lazy('Certificate Profile Selection'),
        [HelpRow(_non_lazy('Certificate Profile'), select, ValueRenderType.PLAIN)],
    )


def build_tls_trust_store_section() -> HelpSection:
    """Builds the TLS trust-store section.

    Raises:
        Http404: If no active Trustpoint TLS-server credential is found or the root CA cert is missing.

    Returns:
        The TLS trust-store section.
    """
    tls = ActiveTrustpointTlsServerCredentialModel.objects.first()
    if not tls or not tls.credential:
        raise Http404(_('Trustpoint TLS server credential is missing.'))

    root = tls.credential.get_last_in_chain()
    if not root:
        raise Http404(_('Root CA certificate is missing.'))
    url = reverse(
        'pki:certificate-file-download-file-name',
        kwargs={'file_format': 'pem', 'pk': root.pk, 'file_name': 'trustpoint-tls-trust-store.pem'},
    )
    btn = format_html('<a class="btn btn-primary w-100" href="{}">{}</a>', url, _('Download TLS Trust-Store'))
    return HelpSection(
        _non_lazy('Download TLS Trust-Store'),
        [HelpRow(_non_lazy('Download TLS Trust-Store'), btn, ValueRenderType.PLAIN)],
    )


# --------------------------------------------------- Base Classes ----------------------------------------------------


class HelpPageStrategy(abc.ABC):
    """Abstract base class for help page strategies."""

    @abc.abstractmethod
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        """Builds the required sections."""


@dataclass(frozen=True)
class HelpContext:
    """Holds shared context data."""

    device: DeviceModel
    domain: DomainModel
    domain_unique_name: str
    public_key_info: oid.PublicKeyInfo
    host_base: str  # https://IP:PORT
    host_cmp_path: str  # {host_base}/.well-known/cmp/p/{domain.unique_name}
    host_est_path: str  # {host_base}/.well-known/est/{domain.unique_name}
    cred_count: int  # Running number to avoid overriding files on the client side


class BaseHelpView(PageContextMixin, DetailView[DeviceModel]):
    """Base help view that constructs the context."""

    template_name = 'help/help_page.html'
    http_method_names = ('get',)
    model = DeviceModel
    context_object_name = 'device'

    page_category = DEVICES_PAGE_CATEGORY
    page_name: str
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        device = self.object
        domain = getattr(device, 'domain', None)
        if not domain:
            raise Http404(_('No domain is configured for this device.'))

        host_base = f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}'
        cred_count = IssuedCredentialModel.objects.filter(device=device).count()

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            device=device,
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=cred_count,
        )

    @override
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data and builds the HelpPage.

        Args:
            kwargs: Passed to super().get_context_data().

        Returns:
            The django context for the detail view.
        """
        context = super().get_context_data(**kwargs)
        if not self.strategy:
            err_msg = _('No strategy configured.')
            raise RuntimeError(err_msg)
        help_context = self._make_context()
        sections, heading = self.strategy.build_sections(help_context=help_context)

        context['help_page'] = HelpPage(heading=heading, sections=sections)
        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value
        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'
        return context


# ------------------------------------- No Onboarding - Help Page Implementations -------------------------------------


class NoOnboardingCmpSharedSecretStrategy(HelpPageStrategy):
    """Strategy for building the no-onboarding cmp shared-secret help page."""

    _allowed_app_cert_profiles: list[ApplicationCertificateProfile]

    def __init__(self, allowed_app_cert_profiles: list[ApplicationCertificateProfile]) -> None:
        """Inits the NoOnboardingCmpSharedSecretApplicationStrategy object by setting the allowed app cert profiles.

        Args:
            allowed_app_cert_profiles: List of allowed application certificate profiles.
        """
        self._allowed_app_cert_profiles = allowed_app_cert_profiles

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.device
        no_onboarding_config = getattr(device, 'no_onboarding_config', None)
        if not no_onboarding_config:
            raise Http404(_('Onboarding is configured for this device.'))
        cmp_shared_secret = no_onboarding_config.cmp_shared_secret
        operation = 'certification'
        base = help_context.host_cmp_path

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Certificate Request URL'),
                    f'{base}/<certificate_profile>/{operation}',
                    ValueRenderType.CODE,
                ),
                HelpRow(_non_lazy('Key Identifier (KID)'), str(device.pk), ValueRenderType.CODE),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
                HelpRow(_non_lazy('Shared-Secret'), cmp_shared_secret, ValueRenderType.CODE),
            ],
        )

        cred = help_context.cred_count

        tls_client_cmd = CmpSharedSecretCommandBuilder.get_tls_client_profile_command(
            host=f'{base}/tls-client/{operation}', pk=device.pk, shared_secret=cmp_shared_secret, cred_number=cred
        )
        tls_server_cmd = CmpSharedSecretCommandBuilder.get_tls_server_profile_command(
            host=f'{base}/tls-server/{operation}', pk=device.pk, shared_secret=cmp_shared_secret, cred_number=cred
        )
        opc_client_cmd = CmpSharedSecretCommandBuilder.get_opc_ua_client_profile_command(
            host=f'{base}/opc-ua-client/{operation}', pk=device.pk, shared_secret=cmp_shared_secret, cred_number=cred
        )
        opc_server_cmd = CmpSharedSecretCommandBuilder.get_opc_ua_server_profile_command(
            host=f'{base}/opc-ua-server/{operation}', pk=device.pk, shared_secret=cmp_shared_secret, cred_number=cred
        )

        def _build_section(
            title: str, cert_profile: ApplicationCertificateProfile, cmd: str, *, hidden: bool = False
        ) -> HelpSection:
            return HelpSection(
                title,
                [
                    HelpRow(_non_lazy('OpenSSL Command'), cmd, ValueRenderType.CODE),
                ],
                css_id=cert_profile.profile_name,
                hidden=hidden,
            )

        sections = [
            summary,
            build_keygen_section(help_context, file_name=''),
            build_profile_select_section(app_cert_profiles=self._allowed_app_cert_profiles),
            _build_section(
                _non_lazy('Certificate Request for a TLS Client Certificates'),
                ApplicationCertificateProfile.TLS_CLIENT,
                tls_client_cmd,
            ),
            _build_section(
                _non_lazy('Certificate Request for a TLS Server Certificates'),
                ApplicationCertificateProfile.TLS_SERVER,
                tls_server_cmd,
                hidden=True,
            ),
            _build_section(
                _non_lazy('Certificate Request for a OPC-UA Client Certificates'),
                ApplicationCertificateProfile.OPC_UA_CLIENT,
                opc_client_cmd,
                hidden=True,
            ),
            _build_section(
                _non_lazy('Certificate Request for a OPC-UA Server Certificates'),
                ApplicationCertificateProfile.OPC_UA_SERVER,
                opc_server_cmd,
                hidden=True,
            ),
        ]
        return sections, _non_lazy('Help - CMP Shared-Secret (HMAC)')


class DeviceNoOnboardingCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = NoOnboardingCmpSharedSecretStrategy(
        allowed_app_cert_profiles=[ApplicationCertificateProfile.TLS_CLIENT, ApplicationCertificateProfile.TLS_SERVER]
    )


class OpcUaGdsNoOnboardingCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = NoOnboardingCmpSharedSecretStrategy(
        allowed_app_cert_profiles=[
            ApplicationCertificateProfile.TLS_CLIENT,
            ApplicationCertificateProfile.TLS_SERVER,
            ApplicationCertificateProfile.OPC_UA_CLIENT,
            ApplicationCertificateProfile.OPC_UA_SERVER,
        ]
    )


class NoOnboardingEstUsernamePasswordStrategy(HelpPageStrategy):
    """Strategy for building the no-onboarding cmp shared-secret help page."""

    _allowed_app_cert_profiles: list[ApplicationCertificateProfile]

    def __init__(self, allowed_app_cert_profiles: list[ApplicationCertificateProfile]) -> None:
        """Inits the NoOnboardingCmpSharedSecretApplicationStrategy object by setting the allowed app cert profiles.

        Args:
            allowed_app_cert_profiles: List of allowed application certificate profiles.
        """
        self._allowed_app_cert_profiles = allowed_app_cert_profiles

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.device
        no_onboarding_config = getattr(device, 'no_onboarding_config', None)
        if not no_onboarding_config:
            raise Http404(_('Onboarding is configured for this device.'))
        est_password = no_onboarding_config.est_password
        operation = 'simpleenroll'
        base = help_context.host_est_path

        def _get_enroll_path(cert_profile: ApplicationCertificateProfile) -> str:
            return f'{base}/{cert_profile.profile_name}/{operation}'

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Certificate Request URL'),
                    f'{base}/<certificate_profile>/{operation}',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    key=('EST-Username'),
                    value=device.common_name,
                    value_render_type=ValueRenderType.CODE,
                ),
                HelpRow(
                    key=('EST-Password'),
                    value=est_password,
                    value_render_type=ValueRenderType.CODE,
                ),
            ],
        )

        cred = help_context.cred_count

        tls_client_cmd = EstUsernamePasswordCommandBuilder.get_tls_client_profile_command(cred_number=cred)
        tls_server_cmd = EstUsernamePasswordCommandBuilder.get_tls_server_profile_command(cred_number=cred)
        opc_client_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_client_profile_command(cred_number=cred)
        opc_server_cmd = EstUsernamePasswordCommandBuilder.get_opc_ua_server_profile_command(cred_number=cred)

        def _build_section(
            title: str, cert_profile: ApplicationCertificateProfile, cmd: str, *, hidden: bool = False
        ) -> HelpSection:
            return HelpSection(
                title,
                [
                    HelpRow(_non_lazy('OpenSSL Command'), cmd, ValueRenderType.CODE),
                    HelpRow(
                        _non_lazy('Enroll certificate with curl'),
                        value=EstUsernamePasswordCommandBuilder.get_curl_enroll_command(
                            est_username=device.common_name,
                            est_password=est_password,
                            host=_get_enroll_path(cert_profile=cert_profile),
                            cred_number=cred,
                        ),
                        value_render_type=ValueRenderType.CODE,
                    ),
                ],
                css_id=cert_profile.profile_name,
                hidden=hidden,
            )

        sections = [
            summary,
            build_tls_trust_store_section(),
            build_keygen_section(help_context, file_name=''),
            build_profile_select_section(app_cert_profiles=self._allowed_app_cert_profiles),
            _build_section(
                _non_lazy('Certificate Request for a TLS Client Certificates'),
                ApplicationCertificateProfile.TLS_CLIENT,
                tls_client_cmd,
            ),
            _build_section(
                _non_lazy('Certificate Request for a TLS Server Certificates'),
                ApplicationCertificateProfile.TLS_SERVER,
                tls_server_cmd,
                hidden=True,
            ),
            _build_section(
                _non_lazy('Certificate Request for a OPC-UA Client Certificates'),
                ApplicationCertificateProfile.OPC_UA_CLIENT,
                opc_client_cmd,
                hidden=True,
            ),
            _build_section(
                _non_lazy('Certificate Request for a OPC-UA Server Certificates'),
                ApplicationCertificateProfile.OPC_UA_SERVER,
                opc_server_cmd,
                hidden=True,
            ),
            HelpSection(
                heading=_non_lazy('Convert the certificate from DER format to PEM format (Optional)'),
                rows=[
                    HelpRow(
                        key=_non_lazy('OpenSSL Command'),
                        value=EstUsernamePasswordCommandBuilder.get_conversion_der_pem_command(cred_number=cred),
                        value_render_type=ValueRenderType.CODE,
                    )
                ],
            ),
        ]
        return sections, _non_lazy('Help - EST (Username & Password)')


class DeviceNoOnboardingEstUsernamePasswordHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = NoOnboardingEstUsernamePasswordStrategy(
        allowed_app_cert_profiles=[ApplicationCertificateProfile.TLS_CLIENT, ApplicationCertificateProfile.TLS_SERVER]
    )


class OpcUaGdsNoOnboardingEstUsernamePasswordHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = NoOnboardingEstUsernamePasswordStrategy(
        allowed_app_cert_profiles=[
            ApplicationCertificateProfile.TLS_CLIENT,
            ApplicationCertificateProfile.TLS_SERVER,
            ApplicationCertificateProfile.OPC_UA_CLIENT,
            ApplicationCertificateProfile.OPC_UA_SERVER,
        ]
    )


# ----------------------------- Onboarding - Domain Credential - Help Page Implementations -----------------------------


class OnboardingDomainCredentialCmpSharedSecretStrategy(HelpPageStrategy):
    """Strategy for building the no-onboarding cmp shared-secret help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.device
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))
        cmp_shared_secret = onboarding_config.cmp_shared_secret
        operation = 'initialization'
        base = help_context.host_cmp_path

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Certificate Request URL'),
                    f'{base}/{operation}',
                    ValueRenderType.CODE,
                ),
                HelpRow(_non_lazy('Key Identifier (KID)'), str(device.pk), ValueRenderType.CODE),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
                HelpRow(_non_lazy('Shared-Secret'), cmp_shared_secret, ValueRenderType.CODE),
            ],
        )

        cmp_ir_cmd = CmpSharedSecretCommandBuilder.get_domain_credential_profile_command(
            host=f'{base}/{operation}',
            pk=device.pk,
            shared_secret=cmp_shared_secret
        )

        openssl_cmp_ir_cmd_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=cmp_ir_cmd,
            value_render_type=ValueRenderType.CODE,
        )

        sections = [
            summary,
            build_keygen_section(help_context, file_name='domain-credential-key.pem'),
            HelpSection(
                heading=_non_lazy('Certificate Request for TLS Client Certificates'),
                rows=[openssl_cmp_ir_cmd_row],
                hidden=False,
                css_id=ApplicationCertificateProfile.TLS_CLIENT.profile_name,
            )
        ]
        return sections, _non_lazy('Help - CMP Shared-Secret (HMAC)')


class DeviceOnboardingDomainCredentialCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = OnboardingDomainCredentialCmpSharedSecretStrategy()

class OpcUaGdsOnboardingDomainCredentialCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = OnboardingDomainCredentialCmpSharedSecretStrategy()


class OnboardingDomainCredentialEstUsernamePasswordStrategy(HelpPageStrategy):
    """Strategy for building the no-onboarding cmp shared-secret help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.device
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))
        est_password = onboarding_config.est_password
        operation = 'simpleenroll'
        base = help_context.host_est_path

        def _get_enroll_path(cert_profile: ApplicationCertificateProfile) -> str:
            return f'{base}/{cert_profile.profile_name}/{operation}'

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Certificate Request URL'),
                    f'{base}/{operation}',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    key=('EST-Username'),
                    value=device.common_name,
                    value_render_type=ValueRenderType.CODE,
                ),
                HelpRow(
                    key=('EST-Password'),
                    value=est_password,
                    value_render_type=ValueRenderType.CODE,
                ),
            ],
        )

        cred = help_context.cred_count

        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_domain_credential_profile_command()

        openssl_req_cmd_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
        )

        enroll_cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_domain_credential_command(
            est_username=device.common_name,
            est_password=est_password,
            host=f'{base}/domaincredential/simpleenroll/',
        )

        enroll_cmd_row = HelpRow(
            key=_non_lazy('Enroll domain credential with curl'), value=enroll_cmd, value_render_type=ValueRenderType.CODE
        )

        openssl_req_cmd_section = HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for the domain credential'),
            rows=[openssl_req_cmd_row, enroll_cmd_row],
            hidden=False,
            css_id=ApplicationCertificateProfile.TLS_CLIENT.profile_name,
        )

        der_to_pem_convertion_section = HelpSection(
            heading=_non_lazy('Convert the certificate from DER format to PEM format (Optional)'),
            rows=[
                HelpRow(
                    key=_non_lazy('OpenSSL Command'),
                    value=EstUsernamePasswordCommandBuilder.get_domain_credential_conversion_der_pem_command(),
                    value_render_type=ValueRenderType.CODE,
                )
            ],
        )

        sections = [
            summary,
            build_tls_trust_store_section(),
            build_keygen_section(help_context, file_name='domain-credential-key.pem'),
            openssl_req_cmd_section,
            der_to_pem_convertion_section
        ]
        return sections, _non_lazy('Help - EST (Username & Password)')


class DeviceOnboardingDomainCredentialEstUsernamePasswordHelpView(BaseHelpView):
    """abc."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = OnboardingDomainCredentialEstUsernamePasswordStrategy()


class OpcUaGdsOnboardingDomainCredentialEstUsernamePasswordHelpView(BaseHelpView):
    """abc."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = OnboardingDomainCredentialEstUsernamePasswordStrategy()


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
            css_id=ApplicationCertificateProfile.TLS_CLIENT.profile_name,
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
            css_id=ApplicationCertificateProfile.TLS_CLIENT.profile_name,
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
            css_id=ApplicationCertificateProfile.TLS_SERVER.profile_name,
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
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.profile_name,
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
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.profile_name,
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
                select_field += format_html(
                    '<option value="{}" selected>{}</option>', profile.profile_name, profile.profile_label
                )
            else:
                select_field += format_html(
                    '<option value="{}">{}</option>', profile.profile_name, profile.profile_label
                )
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
            css_id=ApplicationCertificateProfile.TLS_CLIENT.profile_name,
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
            css_id=ApplicationCertificateProfile.TLS_SERVER.profile_name,
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
            css_id=ApplicationCertificateProfile.OPC_UA_CLIENT.profile_name,
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
            css_id=ApplicationCertificateProfile.OPC_UA_SERVER.profile_name,
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
                select_field += format_html(
                    '<option value="{}" selected>{}</option>', profile.profile_name, profile.profile_label
                )
            else:
                select_field += format_html(
                    '<option value="{}">{}</option>', profile.profile_name, profile.profile_label
                )
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
