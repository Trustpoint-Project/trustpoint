"""This module contains all views concerning the help pages used within the devices app."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, override

from django.http import Http404
from django.utils.translation import gettext as _non_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
from pydantic import ValidationError as PydanticValidationError

from devices.models import DeviceModel, IssuedCredentialModel
from devices.views import PublicKeyInfoMissingErrorMsg
from help_pages.base import (
    HelpContext,
    HelpPageStrategy,
    build_cmp_signer_trust_store_section,
    build_keygen_section,
    build_profile_select_section,
    build_tls_trust_store_section,
)
from help_pages.commands import (
    CmpClientCertificateCommandBuilder,
    CmpSharedSecretCommandBuilder,
    EstClientCertificateCommandBuilder,
    EstUsernamePasswordCommandBuilder,
)
from help_pages.help_section import HelpPage, HelpRow, HelpSection, ValueRenderType
from management.models import TlsSettings
from pki.util.cert_profile import JSONProfileVerifier, ProfileValidationError
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PageContextMixin,
)

if TYPE_CHECKING:
    from typing import Any


# --------------------------------------------------- Base Classes ----------------------------------------------------


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

        allowed_app_profiles = list(
            domain.get_allowed_cert_profiles().exclude(certificate_profile__unique_name='domain_credential'))

        return HelpContext(
            device=device,
            domain=domain,
            domain_unique_name=domain.unique_name,
            allowed_app_profiles=allowed_app_profiles,
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
    """Strategy for building the no-onboarding CMP shared-secret help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
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

        def _build_section(
            title: str, profile_name: str, cmd: str, *, hidden: bool = False
        ) -> HelpSection:
            return HelpSection(
                title,
                [
                    HelpRow(_non_lazy('OpenSSL Command'), cmd, ValueRenderType.CODE),
                ],
                css_id=profile_name,
                hidden=hidden,
            )

        sections = [
            summary,
            build_keygen_section(help_context, file_name=''),
            build_profile_select_section(app_cert_profiles=help_context.allowed_app_profiles),
        ]

        for i, profile in enumerate(help_context.allowed_app_profiles):
            name = profile.alias or profile.certificate_profile.unique_name
            title = profile.certificate_profile.display_name or name

            try:
                cert_profile = json.loads(profile.certificate_profile.profile_json)
                sample_request = JSONProfileVerifier(cert_profile).get_sample_request()

                cmd = CmpSharedSecretCommandBuilder.get_dynamic_cert_profile_command(
                    sample_request=sample_request,
                    host=f'{base}/{name}/{operation}',
                    pk=device.pk,
                    shared_secret=cmp_shared_secret,
                    cred_number=cred,
                )
            except (json.JSONDecodeError, PydanticValidationError, ProfileValidationError, ValueError) as e:
                err_msg = f'The command cannot be generated because the Certificate Profile is malformed: {e}'
                err_sect = HelpSection(
                    _non_lazy(f'Certificate Request for a {title} Certificate'),
                    [
                        HelpRow(_non_lazy('OpenSSL Command'), err_msg, ValueRenderType.PLAIN),
                    ],
                    css_id=name,
                    hidden=(i > 0),
                )
                sections.append(err_sect)
                continue

            sect = _build_section(
                _non_lazy(f'Certificate Request for a {title} Certificate'),
                name,
                cmd,
                hidden=(i > 0),
            )
            sections.append(sect)

        return sections, _non_lazy('Help - Issue Application Certificates using CMP with a shared-secret (HMAC)')


class DeviceNoOnboardingCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = NoOnboardingCmpSharedSecretStrategy()


class OpcUaGdsNoOnboardingCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of no onboarding using CMP shared-secret for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = NoOnboardingCmpSharedSecretStrategy()


class NoOnboardingEstUsernamePasswordStrategy(HelpPageStrategy):
    """Strategy for building the no-onboarding EST username and password help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        no_onboarding_config = getattr(device, 'no_onboarding_config', None)
        if not no_onboarding_config:
            raise Http404(_('Onboarding is configured for this device.'))
        est_password = no_onboarding_config.est_password
        operation = 'simpleenroll'
        base = help_context.host_est_path

        def _get_enroll_path(cert_profile_name: str) -> str:
            return f'{base}/{cert_profile_name}/{operation}'

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

        def _build_section(
            title: str, cert_profile_name: str, cmd: str, *, hidden: bool = False
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
                            host=_get_enroll_path(cert_profile_name=cert_profile_name),
                            cred_number=cred,
                        ),
                        value_render_type=ValueRenderType.CODE,
                    ),
                ],
                css_id=cert_profile_name,
                hidden=hidden,
            )

        sections = [
            summary,
            build_tls_trust_store_section(),
            build_keygen_section(help_context, file_name=''),
            build_profile_select_section(app_cert_profiles=help_context.allowed_app_profiles),
        ]
        for i, profile in enumerate(help_context.allowed_app_profiles):
            name = profile.alias or profile.certificate_profile.unique_name
            title = profile.certificate_profile.display_name or name

            try:
                cert_profile = json.loads(profile.certificate_profile.profile_json)
                sample_request = JSONProfileVerifier(cert_profile).get_sample_request()

                cmd = EstUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
                    sample_request=sample_request,
                    cred_number=cred,
                )
            except (json.JSONDecodeError, PydanticValidationError, ProfileValidationError, ValueError) as e:
                err_msg = f'The command cannot be generated because the Certificate Profile is malformed: {e}'
                err_sect = HelpSection(
                    _non_lazy(f'Certificate Request for a {title} Certificate'),
                    [
                        HelpRow(_non_lazy('OpenSSL Command'), err_msg, ValueRenderType.PLAIN),
                    ],
                    css_id=name,
                    hidden=(i > 0),
                )
                sections.append(err_sect)
                continue

            sect = _build_section(
                _non_lazy(f'Certificate Request for a {title} Certificate'),
                name,
                cmd,
                hidden=(i > 0),
            )
            sections.append(sect)
        sections.append(
            HelpSection(
                heading=_non_lazy('Convert the certificate from PKCS#7 to PEM format (Optional)'),
                rows=[
                    HelpRow(
                        key=_non_lazy('OpenSSL Command'),
                        value=EstUsernamePasswordCommandBuilder.get_conversion_p7_pem_command(cred_number=cred),
                        value_render_type=ValueRenderType.CODE,
                    )
                ],
            )
        )
        return sections, _non_lazy('Help - Issue Application Certificates using EST with username and password')


class DeviceNoOnboardingEstUsernamePasswordHelpView(BaseHelpView):
    """Help view for the case of no onboarding using EST username and password generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = NoOnboardingEstUsernamePasswordStrategy()


class OpcUaGdsNoOnboardingEstUsernamePasswordHelpView(BaseHelpView):
    """Help view for the case of no onboarding using EST username and password for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = NoOnboardingEstUsernamePasswordStrategy()


# --------------------- Onboarding - Domain Credential - Shared Secrets - Help Page Implementations --------------------


class OnboardingDomainCredentialCmpSharedSecretStrategy(HelpPageStrategy):
    """Strategy for building the onboarding CMP shared-secret help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
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
            host=f'{base}/{operation}', pk=device.pk, shared_secret=cmp_shared_secret
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
                css_id='domain_credential',
            ),
        ]
        return sections, _non_lazy('Help - Issue a Domain Credential using CMP with a shared-secret (HMAC)')


class DeviceOnboardingDomainCredentialCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of onboarding using CMP with a domain credential for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = OnboardingDomainCredentialCmpSharedSecretStrategy()


class OpcUaGdsOnboardingDomainCredentialCmpSharedSecretHelpView(BaseHelpView):
    """Help view for the case of onboarding using CMP with a domain credential for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = OnboardingDomainCredentialCmpSharedSecretStrategy()


class OnboardingDomainCredentialEstUsernamePasswordStrategy(HelpPageStrategy):
    """Strategy for building the onboarding est username and password help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))
        est_password = onboarding_config.est_password
        operation = 'simpleenroll'
        base = help_context.host_est_path

        def _get_enroll_path(cert_profile_name: str) -> str:
            return f'{base}/{cert_profile_name}/{operation}'

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

        openssl_req_cmd = EstUsernamePasswordCommandBuilder.get_domain_credential_profile_command()

        openssl_req_cmd_row = HelpRow(
            key=_non_lazy('OpenSSL Command'),
            value=openssl_req_cmd,
            value_render_type=ValueRenderType.CODE,
        )

        enroll_cmd = EstUsernamePasswordCommandBuilder.get_curl_enroll_domain_credential_command(
            est_username=device.common_name,
            est_password=est_password,
            host=f'{base}/domain_credential/simpleenroll/',
        )

        enroll_cmd_row = HelpRow(
            key=_non_lazy('Enroll domain credential with curl'),
            value=enroll_cmd,
            value_render_type=ValueRenderType.CODE,
        )

        openssl_req_cmd_section = HelpSection(
            heading=_non_lazy('Generate PKCS#10 CSR for the domain credential'),
            rows=[openssl_req_cmd_row, enroll_cmd_row],
            hidden=False,
            css_id='domain_credential',
        )

        der_to_pem_convertion_section = HelpSection(
            heading=_non_lazy('Convert the certificate from PKCS#7 to PEM format (Optional)'),
            rows=[
                HelpRow(
                    key=_non_lazy('OpenSSL Command'),
                    value=EstUsernamePasswordCommandBuilder.get_domain_credential_conversion_p7_pem_command(),
                    value_render_type=ValueRenderType.CODE,
                )
            ],
        )

        sections = [
            summary,
            build_tls_trust_store_section(),
            build_keygen_section(help_context, file_name='domain-credential-key.pem'),
            openssl_req_cmd_section,
            der_to_pem_convertion_section,
        ]
        return sections, _non_lazy('Help - Issue a Domain Credential using EST with username and password')


class DeviceOnboardingDomainCredentialEstUsernamePasswordHelpView(BaseHelpView):
    """Help view for the case of onboarding using EST username & password for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = OnboardingDomainCredentialEstUsernamePasswordStrategy()


class OpcUaGdsOnboardingDomainCredentialEstUsernamePasswordHelpView(BaseHelpView):
    """Help view for the case of onboarding using EST username & password for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = OnboardingDomainCredentialEstUsernamePasswordStrategy()


# ------------------------- Onboarding - Application Certificates - Help Page Implementations -------------------------


class ApplicationCertificateWithCmpDomainCredentialStrategy(HelpPageStrategy):
    """Strategy for building the onboarding cmp app certificate help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))
        operation = 'certification'
        base = help_context.host_cmp_path

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Certificate Request URL'),
                    f'{base}/<certificate-profile>/{operation}',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
            ],
        )

        cred = help_context.cred_count

        def _build_section(
            title: str, cert_profile_name: str, cmd: str, *, hidden: bool = False
        ) -> HelpSection:
            return HelpSection(
                title,
                [
                    HelpRow(_non_lazy('OpenSSL Command'), cmd, ValueRenderType.CODE),
                ],
                css_id=cert_profile_name,
                hidden=hidden,
            )

        sections = [
            summary,
            build_cmp_signer_trust_store_section(domain=help_context.domain),
            build_keygen_section(help_context, file_name=''),
            build_profile_select_section(app_cert_profiles=help_context.allowed_app_profiles),
        ]
        for i, profile in enumerate(help_context.allowed_app_profiles):
            name = profile.alias or profile.certificate_profile.unique_name
            title = profile.certificate_profile.display_name or name

            try:
                cert_profile = json.loads(profile.certificate_profile.profile_json)
                sample_request = JSONProfileVerifier(cert_profile).get_sample_request()

                cmd = CmpClientCertificateCommandBuilder.get_dynamic_cert_profile_command(
                    sample_request=sample_request,
                    host=f'{base}/{name}/{operation}',
                    cred_number=cred,
                )
            except (json.JSONDecodeError, PydanticValidationError, ProfileValidationError, ValueError) as e:
                err_msg = f'The command cannot be generated because the Certificate Profile is malformed: {e}'
                err_sect = HelpSection(
                    _non_lazy(f'Certificate Request for a {title} Certificate'),
                    [
                        HelpRow(_non_lazy('OpenSSL Command'), err_msg, ValueRenderType.PLAIN),
                    ],
                    css_id=name,
                    hidden=(i > 0),
                )
                sections.append(err_sect)
                continue

            sect = _build_section(
                _non_lazy(f'Certificate Request for a {title} Certificate'),
                name,
                cmd,
                hidden=(i > 0),
            )
            sections.append(sect)
        return sections, _non_lazy('Help - Issue Application Certificates using CMP with a Domain Credential')


class DeviceApplicationCertificateWithCmpDomainCredentialHelpView(BaseHelpView):
    """Help view for the case of onboarding using CMP with client cert for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = ApplicationCertificateWithCmpDomainCredentialStrategy()


class OpcUaGdsApplicationCertificateWithCmpDomainCredentialHelpView(BaseHelpView):
    """Help view for the case of onboarding using CMP with client cert for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = ApplicationCertificateWithCmpDomainCredentialStrategy()


class ApplicationCertificateWithEstDomainCredentialStrategy(HelpPageStrategy):
    """Strategy for building the onboarding EST username and password help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))
        operation = 'simpleenroll'
        base = help_context.host_est_path

        def _get_enroll_path(cert_profile_name: str) -> str:
            return f'{base}/{cert_profile_name}/{operation}'

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
            ],
        )

        cred = help_context.cred_count

        def _build_section(
            title: str, cert_profile_name: str, cmd: str, *, hidden: bool = False
        ) -> HelpSection:
            return HelpSection(
                title,
                [
                    HelpRow(_non_lazy('OpenSSL Command'), cmd, ValueRenderType.CODE),
                    HelpRow(
                        _non_lazy('Enroll certificate with curl'),
                        value=EstClientCertificateCommandBuilder.get_curl_enroll_application_credential(
                            host=_get_enroll_path(cert_profile_name=cert_profile_name),
                            cred_number=cred,
                        ),
                        value_render_type=ValueRenderType.CODE,
                    ),
                ],
                css_id=cert_profile_name,
                hidden=hidden,
            )

        sections = [
            summary,
            build_tls_trust_store_section(),
            build_keygen_section(help_context, file_name=''),
            build_profile_select_section(app_cert_profiles=help_context.allowed_app_profiles),
        ]
        for i, profile in enumerate(help_context.allowed_app_profiles):
            name = profile.alias or profile.certificate_profile.unique_name
            title = profile.certificate_profile.display_name or name

            try:
                cert_profile = json.loads(profile.certificate_profile.profile_json)
                sample_request = JSONProfileVerifier(cert_profile).get_sample_request()

                cmd = EstUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
                    sample_request=sample_request,
                    cred_number=cred,
                )
            except (json.JSONDecodeError, PydanticValidationError, ProfileValidationError, ValueError) as e:
                err_msg = f'The command cannot be generated because the Certificate Profile is malformed: {e}'
                err_sect = HelpSection(
                    _non_lazy(f'Certificate Request for a {title} Certificate'),
                    [
                        HelpRow(_non_lazy('OpenSSL Command'), err_msg, ValueRenderType.PLAIN),
                    ],
                    css_id=name,
                    hidden=(i > 0),
                )
                sections.append(err_sect)
                continue

            sect = _build_section(
                _non_lazy(f'Certificate Request for a {title} Certificate'),
                name,
                cmd,
                hidden=(i > 0),
            )
            sections.append(sect)
        sections.append(
            HelpSection(
                heading=_non_lazy('Convert the certificate from PKCS#7 to PEM format (Optional)'),
                rows=[
                    HelpRow(
                        key=_non_lazy('OpenSSL Command'),
                        value=EstUsernamePasswordCommandBuilder.get_conversion_p7_pem_command(cred_number=cred),
                        value_render_type=ValueRenderType.CODE,
                    )
                ],
            )
        )
        return sections, _non_lazy('Help - Issue Application Certificates using EST with a Domain Credential')


class DeviceApplicationCertificateWithEstDomainCredentialHelpView(BaseHelpView):
    """Help view for the case of onboarding using EST with client cert for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = ApplicationCertificateWithEstDomainCredentialStrategy()


class OpcUaGdsApplicationCertificateWithEstDomainCredentialHelpView(BaseHelpView):
    """Help view for the case of onboarding using EST with client cert for OPC-UA GDS abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = ApplicationCertificateWithEstDomainCredentialStrategy()
