"""This module contains all views concerning the help pages used within the devices app."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import TYPE_CHECKING, override

from cryptography import x509
from django.contrib import messages
from django.core.management import call_command
from django.http import FileResponse, Http404, HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from django.utils.safestring import SafeString
from django.utils.translation import gettext as _non_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.base import TemplateView, View
from django.views.generic.detail import DetailView
from pydantic import ValidationError as PydanticValidationError

from devices.models import DeviceModel
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
    AokiCmpIDevIDCommandBuilder,
    AokiEstIDevIDCommandBuilder,
    CmpClientCertificateCommandBuilder,
    CmpSharedSecretCommandBuilder,
    EstClientCertificateCommandBuilder,
    EstUsernamePasswordCommandBuilder,
    RestClientCertificateCommandBuilder,
    RestUsernamePasswordCommandBuilder,
)
from help_pages.forms import IpAddressForm
from help_pages.help_section import HelpPage, HelpRow, HelpSection, ValueRenderType
from pki.models import IssuedCredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from pki.util.cert_profile import JSONProfileVerifier, ProfileValidationError
from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    DEVICES_PAGE_ZERO_TOUCH_SUBCATEGORY,
    PageContextMixin,
)

if TYPE_CHECKING:
    from typing import Any

    from pki.models import CaModel, CredentialModel


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

    def _make_context(self, host_ip: str = '127.0.0.1') -> HelpContext:
        device = self.object
        domain = getattr(device, 'domain', None)
        if not domain:
            raise Http404(_('No domain is configured for this device.'))

        host_base = f'https://{host_ip}:{self.request.META.get("SERVER_PORT", "443")}'
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
        ips = []
        try:
            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.get(id=1)
            credential_model: CredentialModel | None = active_tls.credential

            if not credential_model:
                messages.error(self.request, 'Active TLS has no credential')
            else:
                cert = credential_model.get_certificate_serializer().as_crypto()
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                ips = [
                    str(entry.value)
                    for entry in san.value
                    if isinstance(entry, x509.IPAddress) and isinstance(entry.value, ipaddress.IPv4Address)
                ]
        except ActiveTrustpointTlsServerCredentialModel.DoesNotExist:
            messages.error(self.request, 'Active TLS record not found')
        except AttributeError as e:
            messages.error(self.request, f'Invalid credential or certificate: {e}')
        except ValueError as e:
            messages.error(self.request, f'Certificate parsing error: {e}')
        host_ip = '127.0.0.1'
        if not ips:
            ips.append(host_ip)
        data = self.request.GET.dict()
        form = IpAddressForm(ip_choices=ips, data=data or None, initial={'host_ip': host_ip})
        if form.is_bound and form.is_valid():
            host_ip = form.cleaned_data['host_ip']
        elif form.is_bound:
            messages.error(self.request, 'Given IP address is not valid. Setting to 127.0.0.1')

        help_context = self._make_context(host_ip)

        sections, heading = self.strategy.build_sections(help_context=help_context)

        context['help_page'] = HelpPage(heading=heading, sections=sections)
        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value
        context['ValueRenderType_HTML'] = ValueRenderType.HTML.value
        context['clm_url'] = f'{self.page_category}:{self.page_name}_certificate_lifecycle_management'
        context['form'] = form
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
                cert_profile = profile.certificate_profile.profile
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
                cert_profile = profile.certificate_profile.profile
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
                cert_profile = profile.certificate_profile.profile
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
                cert_profile = profile.certificate_profile.profile
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


# ----------------------------- No Onboarding - REST Username/Password Help Page Implementations ---------------------


class NoOnboardingRestUsernamePasswordStrategy(HelpPageStrategy):
    """Strategy for building the no-onboarding REST username/password help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        no_onboarding_config = getattr(device, 'no_onboarding_config', None)
        if not no_onboarding_config:
            raise Http404(_('Onboarding is configured for this device.'))
        est_password = no_onboarding_config.est_password
        host_base = help_context.host_base
        domain_name = help_context.domain_unique_name

        def _get_enroll_path(cert_profile_name: str) -> str:
            return f'{host_base}/rest/{domain_name}/{cert_profile_name}/enroll/'

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Certificate Enrollment URL'),
                    f'{host_base}/rest/{domain_name}/<certificate_profile>/enroll/',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    key=_non_lazy('REST-Username'),
                    value=device.common_name,
                    value_render_type=ValueRenderType.CODE,
                ),
                HelpRow(
                    key=_non_lazy('REST-Password'),
                    value=est_password,
                    value_render_type=ValueRenderType.CODE,
                ),
            ],
        )

        cred = help_context.cred_count

        def _build_section(
            title: str, cert_profile_name: str, csr_cmd: str, *, hidden: bool = False
        ) -> HelpSection:
            return HelpSection(
                title,
                [
                    HelpRow(_non_lazy('Generate CSR'), csr_cmd, ValueRenderType.CODE),
                    HelpRow(
                        _non_lazy('Enroll certificate with curl'),
                        value=RestUsernamePasswordCommandBuilder.get_curl_enroll_command(
                            rest_username=device.common_name,
                            rest_password=est_password,
                            host=_get_enroll_path(cert_profile_name=cert_profile_name),
                            cred_number=cred,
                        ),
                        value_render_type=ValueRenderType.CODE,
                    ),
                    HelpRow(
                        _non_lazy('Extract certificate from JSON response'),
                        value=RestUsernamePasswordCommandBuilder.get_extract_cert_command(cred_number=cred),
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
                cert_profile = profile.certificate_profile.profile
                sample_request = JSONProfileVerifier(cert_profile).get_sample_request()
                csr_cmd = RestUsernamePasswordCommandBuilder.get_dynamic_cert_profile_command(
                    cred_number=cred,
                    sample_request=sample_request,
                )
            except (json.JSONDecodeError, PydanticValidationError, ProfileValidationError, ValueError) as e:
                err_msg = f'The command cannot be generated because the Certificate Profile is malformed: {e}'
                sections.append(HelpSection(
                    _non_lazy(f'Certificate Request for a {title} Certificate'),
                    [HelpRow(_non_lazy('Generate CSR'), err_msg, ValueRenderType.PLAIN)],
                    css_id=name,
                    hidden=(i > 0),
                ))
                continue

            sections.append(_build_section(
                _non_lazy(f'Certificate Request for a {title} Certificate'),
                name,
                csr_cmd,
                hidden=(i > 0),
            ))

        return sections, _non_lazy('Help - Issue Application Certificates using REST with username and password')


class DeviceNoOnboardingRestUsernamePasswordHelpView(BaseHelpView):
    """Help view for no-onboarding REST username/password for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = NoOnboardingRestUsernamePasswordStrategy()


class OpcUaGdsNoOnboardingRestUsernamePasswordHelpView(BaseHelpView):
    """Help view for no-onboarding REST username/password for OPC-UA GDS device abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = NoOnboardingRestUsernamePasswordStrategy()


# -------------------- Onboarding - Domain Credential - REST Username/Password - Help Page Implementations ----------


class OnboardingDomainCredentialRestUsernamePasswordStrategy(HelpPageStrategy):
    """Strategy for building the onboarding REST username/password domain-credential help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))
        est_password = onboarding_config.est_password
        host_base = help_context.host_base
        domain_name = help_context.domain_unique_name
        enroll_url = f'{host_base}/rest/{domain_name}/domain_credential/enroll/'

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Domain Credential Enrollment URL'),
                    enroll_url,
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    key=_non_lazy('REST-Username'),
                    value=device.common_name,
                    value_render_type=ValueRenderType.CODE,
                ),
                HelpRow(
                    key=_non_lazy('REST-Password'),
                    value=est_password,
                    value_render_type=ValueRenderType.CODE,
                ),
            ],
        )

        csr_cmd = RestUsernamePasswordCommandBuilder.get_domain_credential_csr_command()
        curl_cmd = RestUsernamePasswordCommandBuilder.get_curl_enroll_domain_credential_command(
            rest_username=device.common_name,
            rest_password=est_password,
            host=enroll_url,
        )
        extract_cmd = RestUsernamePasswordCommandBuilder.get_extract_domain_credential_command()

        sections = [
            summary,
            build_tls_trust_store_section(),
            build_keygen_section(help_context, file_name='domain-credential-key.pem'),
            HelpSection(
                heading=_non_lazy('Domain Credential Certificate Request'),
                rows=[
                    HelpRow(_non_lazy('Generate CSR'), csr_cmd, ValueRenderType.CODE),
                    HelpRow(_non_lazy('Enroll with curl'), curl_cmd, ValueRenderType.CODE),
                    HelpRow(_non_lazy('Extract certificate from JSON response'), extract_cmd, ValueRenderType.CODE),
                ],
                css_id='domain_credential',
            ),
        ]
        return sections, _non_lazy('Help - Issue a Domain Credential using REST with username and password')


class DeviceOnboardingDomainCredentialRestUsernamePasswordHelpView(BaseHelpView):
    """Help view for onboarding using REST username/password domain credential for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = OnboardingDomainCredentialRestUsernamePasswordStrategy()


class OpcUaGdsOnboardingDomainCredentialRestUsernamePasswordHelpView(BaseHelpView):
    """Help view for onboarding using REST username/password domain credential for OPC-UA GDS device abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = OnboardingDomainCredentialRestUsernamePasswordStrategy()


# --------------------- Application Certificates - REST mTLS Domain Credential - Help Page Implementations -----------


class ApplicationCertificateWithRestDomainCredentialStrategy(HelpPageStrategy):
    """Strategy for building the onboarding REST app-cert help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))
        host_base = help_context.host_base
        domain_name = help_context.domain_unique_name

        def _get_enroll_path(cert_profile_name: str) -> str:
            return f'{host_base}/rest/{domain_name}/{cert_profile_name}/enroll/'

        def _get_reenroll_path(cert_profile_name: str) -> str:
            return f'{host_base}/rest/{domain_name}/{cert_profile_name}/reenroll/'

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Initial Enrollment URL'),
                    f'{host_base}/rest/{domain_name}/<certificate_profile>/enroll/',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Renewal URL'),
                    f'{host_base}/rest/{domain_name}/<certificate_profile>/reenroll/',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Authentication for Enrollment'),
                    _non_lazy('mTLS with domain credential'),
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Authentication for Renewal'),
                    _non_lazy('mTLS with domain credential OR previously issued application certificate'),
                    ValueRenderType.PLAIN,
                ),
            ],
        )

        cred = help_context.cred_count

        def _build_section(
            title: str, cert_profile_name: str, csr_cmd: str, *, hidden: bool = False
        ) -> HelpSection:
            return HelpSection(
                title,
                [
                    HelpRow(_non_lazy('Generate CSR'), csr_cmd, ValueRenderType.CODE),
                    HelpRow(
                        _non_lazy('Enroll certificate with curl (mTLS domain credential)'),
                        value=RestClientCertificateCommandBuilder.get_curl_enroll_command(
                            host=_get_enroll_path(cert_profile_name=cert_profile_name),
                            cred_number=cred,
                        ),
                        value_render_type=ValueRenderType.CODE,
                    ),
                    HelpRow(
                        _non_lazy('Re-enroll / renew certificate with curl (mTLS domain credential)'),
                        value=RestClientCertificateCommandBuilder.get_curl_reenroll_command(
                            host=_get_reenroll_path(cert_profile_name=cert_profile_name),
                            cred_number=cred,
                        ),
                        value_render_type=ValueRenderType.CODE,
                    ),
                    HelpRow(
                        _non_lazy('Re-enroll / renew with previous application certificate'),
                        value=_non_lazy(
                            'Replace domain-credential-certificate.pem with the previously issued certificate, '
                            'and domain-credential-key.pem with its corresponding private key.'
                        ),
                        value_render_type=ValueRenderType.PLAIN,
                    ),
                    HelpRow(
                        _non_lazy('Extract certificate from JSON response'),
                        value=RestClientCertificateCommandBuilder.get_extract_cert_command(cred_number=cred),
                        value_render_type=ValueRenderType.CODE,
                    ),
                    HelpRow(
                        _non_lazy('Extract certificate chain from JSON response'),
                        value=RestClientCertificateCommandBuilder.get_extract_cert_chain_command(
                            cred_number=cred
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
                cert_profile = profile.certificate_profile.profile
                sample_request = JSONProfileVerifier(cert_profile).get_sample_request()
                csr_cmd = RestClientCertificateCommandBuilder.get_dynamic_cert_profile_command(
                    cred_number=cred,
                    sample_request=sample_request,
                )
            except (json.JSONDecodeError, PydanticValidationError, ProfileValidationError, ValueError) as e:
                err_msg = f'The command cannot be generated because the Certificate Profile is malformed: {e}'
                sections.append(HelpSection(
                    _non_lazy(f'Certificate Request for a {title} Certificate'),
                    [HelpRow(_non_lazy('Generate CSR'), err_msg, ValueRenderType.PLAIN)],
                    css_id=name,
                    hidden=(i > 0),
                ))
                continue

            sections.append(_build_section(
                _non_lazy(f'Certificate Request for a {title} Certificate'),
                name,
                csr_cmd,
                hidden=(i > 0),
            ))

        return sections, _non_lazy('Help - Issue Application Certificates using REST with a Domain Credential')


class DeviceApplicationCertificateWithRestDomainCredentialHelpView(BaseHelpView):
    """Help view for application certs using REST with client cert for generic device abstractions."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = ApplicationCertificateWithRestDomainCredentialStrategy()


class OpcUaGdsApplicationCertificateWithRestDomainCredentialHelpView(BaseHelpView):
    """Help view for application certs using REST with client cert for OPC-UA GDS device abstractions."""

    page_name = DEVICES_PAGE_OPC_UA_SUBCATEGORY
    strategy = ApplicationCertificateWithRestDomainCredentialStrategy()


class OpcUaGdsPushOnboardingStrategy(HelpPageStrategy):
    """Strategy for building the OPC UA GDS Push onboarding help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        device = help_context.get_device_or_http_404()
        onboarding_config = getattr(device, 'onboarding_config', None)
        if not onboarding_config:
            raise Http404(_('Onboarding is not configured for this device.'))

        sections = [
            self._build_summary_section(help_context),
            self._build_ca_hierarchy_section(device),
            self._build_download_section(device),
            self._build_actions_section(device),
        ]

        return sections, _non_lazy('Help - OPC UA GDS Push Certificate Management')

    def _build_summary_section(self, help_context: HelpContext) -> HelpSection:
        """Build the summary section with basic device information."""
        return HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Protocol'),
                    'OPC UA GDS Push',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Device Type'),
                    'OPC UA GDS Push Device',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Domain'),
                    help_context.domain_unique_name,
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
            ],
        )

    def _build_actions_section(self, device: DeviceModel) -> HelpSection:
        """Build the actions section with available operations."""
        has_domain_credential = IssuedCredentialModel.objects.filter(
            device=device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL
        ).exists()

        discover_server_url = reverse(
            'devices:devices_discover_server',
            kwargs={'pk': device.pk}
        )

        discover_html = (
            '<form method="post" action="' + discover_server_url + '" style="display: inline;">'
            'CSRF_TOKEN_PLACEHOLDER'
            '<button type="submit" class="btn btn-info">Discover Server</button>'
            '</form>'
            '<p class="text-muted mt-2">Connects to the OPC UA server without authentication '
            'to retrieve server information and certificates for initial configuration.</p>'
        )

        if has_domain_credential:
            update_trustlist_url = reverse(
                'devices:devices_update_trustlist',
                kwargs={'pk': device.pk}
            )
            update_cert_url = reverse(
                'devices:devices_update_server_certificate',
                kwargs={'pk': device.pk}
            )

            trustlist_html = (
                '<form method="post" action="' + update_trustlist_url + '" style="display: inline;">'
                'CSRF_TOKEN_PLACEHOLDER'
                '<button type="submit" class="btn btn-primary">Update Trustlist</button>'
                '</form>'
                '<p class="text-muted mt-2">Updates the device\'s trust list with CA certificates '
                'and CRLs from the associated truststore.</p>'
            )

            cert_html = (
                '<form method="post" action="' + update_cert_url + '" style="display: inline;">'
                'CSRF_TOKEN_PLACEHOLDER'
                '<button type="submit" class="btn btn-primary">Update Server Certificate</button>'
                '</form>'
                '<p class="text-muted mt-2">Generates a new CSR on the server, signs it with the '
                'domain CA, and updates the server certificate.</p>'
            )

            return HelpSection(
                _non_lazy('Available Actions'),
                [
                    HelpRow(
                        _non_lazy('Discover Server'),
                        discover_html,
                        ValueRenderType.HTML,
                    ),
                    HelpRow(
                        _non_lazy('Update Trustlist'),
                        trustlist_html,
                        ValueRenderType.HTML,
                    ),
                    HelpRow(
                        _non_lazy('Update Server Certificate'),
                        cert_html,
                        ValueRenderType.HTML,
                    ),
                ],
            )

        return HelpSection(
            _non_lazy('Available Actions'),
            [
                HelpRow(
                    _non_lazy('Discover Server'),
                    discover_html,
                    ValueRenderType.HTML,
                ),
                HelpRow(
                    _non_lazy('Domain Credential Required'),
                    'Before you can update the trustlist or server certificate, you must first issue '
                    'a domain credential for this device. This credential is used to authenticate '
                    'securely with the OPC UA server.',
                    ValueRenderType.PLAIN,
                ),
            ],
        )

    def _build_ca_hierarchy_html(self, ca_chain: list[CaModel]) -> tuple[str, bool]:
        """Build HTML representation of CA hierarchy and check for missing CRLs.

        Args:
            ca_chain: List of CA models in reverse order.

        Returns:
            Tuple of (hierarchy_html, has_missing_crl).
        """
        hierarchy_html = (
            '<div style="font-family: monospace;">'
            '<strong>Certificate Authority Hierarchy:</strong><br>'
        )

        has_missing_crl = False
        for idx, ca in enumerate(ca_chain):
            try:
                if not ca.ca_certificate_model:
                    continue
                cert_serializer = ca.ca_certificate_model.get_certificate_serializer()
                cert_crypto = cert_serializer.as_crypto()

                common_name = cert_crypto.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if common_name:
                    value = common_name[0].value
                    cn_value = value.decode('utf-8') if isinstance(value, bytes) else value
                else:
                    cn_value = ca.unique_name

                crl_status = 'MISSING'
                crl_link = ''
                if ca.crl_pem:
                    try:
                        x509.load_pem_x509_crl(ca.crl_pem.encode())
                        active_crl = ca.get_active_crl()
                        if active_crl:
                            crl_detail_url = reverse('pki:crl-detail', kwargs={'pk': active_crl.pk})
                            crl_link = f'<a href="{crl_detail_url}" target="_blank">CRL</a> '
                        crl_status = 'OK'
                    except (ValueError, TypeError):
                        crl_status = 'INVALID'
                else:
                    has_missing_crl = True

                ca_detail_url = reverse('pki:issuing_cas-detail', kwargs={'pk': ca.pk})
                indent = '&nbsp;' * (idx * 4)
                hierarchy_html += (
                    f'{indent}└─ <a href="{ca_detail_url}" target="_blank">{cn_value}</a> '
                    f'[{crl_link}{crl_status}]<br>'
                )

            except (ValueError, TypeError, AttributeError):
                continue

        hierarchy_html += '</div>'
        return hierarchy_html, has_missing_crl

    def _build_ca_hierarchy_section(self, device: DeviceModel) -> HelpSection:
        """Build the CA hierarchy section with certificate chain information."""
        if not (device.domain and device.domain.issuing_ca):
            return HelpSection(
                _non_lazy('CA Certificates'),
                [
                    HelpRow(
                        _non_lazy('No CA Configured'),
                        'No issuing CA is configured for this device.',
                        ValueRenderType.PLAIN,
                    ),
                ],
            )

        try:
            ca_chain = device.domain.issuing_ca.get_ca_chain_from_truststore()
            ca_chain = list(reversed(ca_chain))

            hierarchy_html, has_missing_crl = self._build_ca_hierarchy_html(ca_chain)

            rows = [

                HelpRow(
                    _non_lazy('Certificate Chain'),
                    hierarchy_html,
                    ValueRenderType.HTML,
                ),
            ]

            if has_missing_crl:
                rows.append(
                    HelpRow(
                        _non_lazy('Warning'),
                        '<div class="alert alert-warning" role="alert">'
                        '<strong>CRL Missing:</strong> One or more Certificate Authorities in the chain '
                        'are missing Certificate Revocation Lists (CRLs). CRLs are mandatory for OPC UA '
                        'GDS Push trustlist operations. Please generate CRLs for all CAs before '
                        'proceeding with trustlist updates.'
                        '</div>',
                        ValueRenderType.HTML,
                    )
                )

            return HelpSection(
                _non_lazy('CA Hierarchy'),
                rows,
            )

        except ValueError:
            return HelpSection(
                _non_lazy('CA Certificates'),
                [
                    HelpRow(
                        _non_lazy('Error'),
                        'Invalid truststore configuration for the issuing CA.',
                        ValueRenderType.PLAIN,
                    ),
                ],
            )

    def _build_download_section(self, device: DeviceModel) -> HelpSection:
        """Build the download section for trust bundle."""
        if device.domain and device.domain.issuing_ca:
            download_url = reverse(
                'devices:trust_bundle_download',
                kwargs={'pk': device.domain.issuing_ca.pk}
            )
            download_html = (
                f'<a href="{download_url}" class="btn btn-primary">Download Trust Bundle</a>'
                '<p class="text-muted mt-2">Download a ZIP file containing all CA certificates '
                'and CRLs in DER format for use with OPC UA servers.</p>'
            )
            return HelpSection(
                _non_lazy('Download Trust Bundle'),
                [
                    HelpRow(
                        _non_lazy('Trust Bundle Download'),
                        download_html,
                        ValueRenderType.HTML,
                    ),
                ],
            )

        return HelpSection(
            _non_lazy('Download Trust Bundle'),
            [
                HelpRow(
                    _non_lazy('Trust Bundle Download'),
                    '<p class="text-muted">No issuing CA configured for this device.</p>',
                    ValueRenderType.HTML,
                ),
            ],
        )

    def _build_renewal_settings_section(self, device: DeviceModel) -> HelpSection:
        """Build the periodic server certificate and trustlist renewal settings section.

        Renders an inline HTML form that posts to the cert-renewal-settings endpoint,
        allowing the user to enable/disable periodic renewal and configure the interval.
        Both the server certificate and the trustlist are updated on each renewal cycle.
        When periodic updates are enabled, the section also shows when the next update
        is scheduled to run.

        :param device: The OPC UA GDS Push device instance.
        :return: A HelpSection containing the renewal configuration form.
        """
        renewal_url = reverse(
            'devices:devices_cert_renewal_settings',
            kwargs={'pk': device.pk}
        )

        enabled = device.opc_gds_push_enable_periodic_update
        interval = device.opc_gds_push_renewal_interval
        next_run = device.opc_gds_push_last_update_scheduled_at

        checked_attr = 'checked' if enabled else ''

        if enabled and next_run is not None:
            now = timezone.now()
            if next_run > now:
                next_run_html = (
                    f'<span class="badge bg-success me-2">Enabled</span>'
                    f'<span>{next_run.strftime("%Y-%m-%d %H:%M UTC")}</span>'
                )
            else:
                next_run_html = (
                    '<span class="badge bg-warning text-dark me-2">Pending</span>'
                    '<span>Scheduled — awaiting worker execution</span>'
                )
        elif enabled:
            next_run_html = (
                '<span class="badge bg-secondary me-2">Enabled</span>'
                '<span>Not yet scheduled — save settings to schedule the first update</span>'
            )
        else:
            next_run_html = '<span class="badge bg-secondary">Disabled</span>'

        form_html = (
            f'<form method="post" action="{renewal_url}">'
            'CSRF_TOKEN_PLACEHOLDER'
            '<div class="mb-3">'
            '<div class="form-check form-switch mb-2">'
            f'  <input class="form-check-input" type="checkbox" role="switch" '
            f'         id="enablePeriodicRenewal" name="opc_gds_push_enable_periodic_update" {checked_attr}>'
            f'  <label class="form-check-label" for="enablePeriodicRenewal">'
            f'    Enable Periodic Server Certificate &amp; Trustlist Renewal'
            f'  </label>'
            '</div>'
            '<label for="renewalInterval" class="form-label mt-2">Renewal Interval (hours)</label>'
            f'<input type="number" class="form-control" id="renewalInterval" '
            f'       name="opc_gds_push_renewal_interval" min="1" value="{interval}" '
            '       style="max-width: 200px;">'
            '<div class="form-text text-muted">'
            '  How often the server certificate and trustlist are automatically renewed. Minimum 1 hour.'
            '</div>'
            '</div>'
            '<button type="submit" class="btn btn-primary">Save Renewal Settings</button>'
            '</form>'
        )

        return HelpSection(
            _non_lazy('Periodic Server Certificate & Trustlist Renewal'),
            [
                HelpRow(
                    _non_lazy('Next Scheduled Update'),
                    next_run_html,
                    ValueRenderType.HTML,
                ),
                HelpRow(
                    _non_lazy('Renewal Configuration'),
                    form_html,
                    ValueRenderType.HTML,
                ),
            ],
        )


class OpcUaGdsPushApplicationCertificateStrategy(OpcUaGdsPushOnboardingStrategy):
    """Strategy for the OPC UA GDS Push application certificate help page.

    Extends the base onboarding strategy with a periodic server certificate
    renewal configuration section.
    """

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        sections, heading = super().build_sections(help_context=help_context)
        device = help_context.get_device_or_http_404()
        sections.append(self._build_renewal_settings_section(device))
        return sections, heading


class OpcUaGdsPushApplicationCertificateHelpView(BaseHelpView):
    """Help view for OPC UA GDS Push application certificates."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = OpcUaGdsPushApplicationCertificateStrategy()


class OpcUaGdsPushOnboardingHelpView(BaseHelpView):
    """Help view for OPC UA GDS Push onboarding."""

    page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY
    strategy = OpcUaGdsPushOnboardingStrategy()

class AokiCmpIDevIDStrategy(HelpPageStrategy):
    """Strategy for building the AOKI CMP with IDevID help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        """Build help sections for AOKI with CMP (IDevID authentication)."""
        device_requirements = HelpSection(
            _non_lazy('Device Requirements'),
            [
                HelpRow(
                    _non_lazy('IDevID Certificate'),
                    'The device must have a valid IDevID (Initial Device Identifier) certificate issued by the '
                    'device manufacturer. This certificate is used for CMP client authentication.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('IDevID Private Key'),
                    'The private key corresponding to the IDevID certificate must be available on the device.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('DevOwnerID Trust Chain'),
                    'The device must have the trust chain of the DevOwnerID certificate. This is used to validate '
                    'the server certificate during the CMP communication.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('mDNS Client'),
                    'The device must support mDNS (Multicast DNS) to discover the Trustpoint server.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Network Access'),
                    'The device must have network access to the Trustpoint server over CMP protocol '
                    f'({help_context.host_cmp_path}).',
                    ValueRenderType.PLAIN,
                ),
            ],
        )

        trustpoint_requirements = HelpSection(
            _non_lazy('Trustpoint Requirements'),
            [
                HelpRow(
                    _non_lazy('DevOwnerID Configuration'),
                    'A DevOwnerID must be configured in Trustpoint with the corresponding certificate and '
                    'private key.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('IDevID Truststore'),
                    'A truststore must be configured in Trustpoint containing the trust chain of the IDevID '
                    'manufacturer certificate.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Registration Pattern'),
                    'The truststore must have a registration pattern configured (e.g., a UUID or other '
                    'unique identifier) to match incoming IDevID certificates.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Domain Mapping'),
                    "The domain is automatically configured through the truststore's registration pattern. "
                    'Ensure the domain has valid certificate profiles configured.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('mDNS Responder'),
                    'An mDNS responder must be running so that devices can discover Trustpoint via mDNS. '
                    'This is an additional component that needs to be deployed as a separate Docker container. '
                    'A ready-to-use Docker Compose file is provided in the Trustpoint repository: '
                    'docker-compose.mdns.yml '
                    '(https://github.com/Trustpoint-Project/trustpoint/blob/main/docker-compose.mdns.yml). '
                    'Note: this does not work with Docker Desktop.',
                    ValueRenderType.PLAIN,
                ),
            ],
        )

        how_it_works = HelpSection(
            _non_lazy('How AOKI with CMP Works'),
            [
                HelpRow(
                    _non_lazy('Step 1: Device Discovery'),
                    '1. Device boots and sends mDNS query to discover Trustpoint server\n'
                    '2. Device receives server address of Trustpoint',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Step 2: IDevID Authentication'),
                    '3. Device sends CMP Initial Request (IR) with generated key pair\n'
                    '4. Request is signed using the IDevID private key\n'
                    '5. Server validates the signature against the configured truststore and registration pattern',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Step 3: Certificate Issuance'),
                    '6. Server verifies the IDevID and issues a domain credential\n'
                    '7. CMP response is signed with the DevOwnerID certificate\n'
                    '8. Device receives a domain credential',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Step 4: Device Verification'),
                    '9. Device verifies the signature of the DevOwnerID and its validity for the IDevID',
                    ValueRenderType.PLAIN,
                ),
            ],
        )

        keygen_cmd = AokiCmpIDevIDCommandBuilder.get_keygen_command()
        cmp_ir_cmd = AokiCmpIDevIDCommandBuilder.get_cmp_ir_command(
            help_context.host_cmp_path
        )

        example_commands = HelpSection(
            _non_lazy('Example Commands'),
            [
                HelpRow(
                    _non_lazy('Step 1: Generate Key Pair'),
                    keygen_cmd,
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Step 2: Execute CMP Initial Request'),
                    cmp_ir_cmd,
                    ValueRenderType.CODE,
                ),
            ],
        )

        return (
            [device_requirements, trustpoint_requirements, how_it_works, example_commands],
            _non_lazy('AOKI with CMP - IDevID Authentication'),
        )


class AokiEstIDevIDStrategy(HelpPageStrategy):
    """Strategy for building the AOKI EST with IDevID help page."""

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        """Build help sections for AOKI with EST (IDevID authentication)."""
        device_requirements = HelpSection(
            _non_lazy('Device Requirements'),
            [
                HelpRow(
                    _non_lazy('IDevID Certificate'),
                    'The device must have a valid IDevID (Initial Device Identifier) certificate issued by the '
                    'device manufacturer. This certificate is used for mutual TLS (mTLS) authentication.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('IDevID Private Key'),
                    'The private key corresponding to the IDevID certificate must be available on the device.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('mDNS Client'),
                    'The device must support mDNS (Multicast DNS) to discover the Trustpoint server. '
                    'Ensure mDNS is enabled on your device and network.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Network Access'),
                    'The device must have network access to the Trustpoint server over EST protocol (TLS) '
                    f'({help_context.host_est_path}).',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('TLS Support'),
                    'The device must support TLS 1.2 or higher for secure communication with the server.',
                    ValueRenderType.PLAIN,
                ),
            ],
        )

        trustpoint_requirements = HelpSection(
            _non_lazy('Trustpoint Requirements'),
            [
                HelpRow(
                    _non_lazy('DevOwnerID Configuration'),
                    'A DevOwnerID must be configured in Trustpoint with the corresponding certificate and '
                    'private key.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('IDevID Truststore'),
                    'A truststore must be configured in Trustpoint containing the trust chain of the IDevID '
                    'manufacturer certificate.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Registration Pattern'),
                    'The truststore must have a registration pattern configured (e.g., a UUID or other '
                    'unique identifier) to match incoming IDevID certificates.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Domain Mapping'),
                    "The domain is automatically configured through the truststore's registration pattern. "
                    'Ensure the domain has valid certificate profiles configured.',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('mDNS Responder'),
                    'An mDNS responder must be running so that devices can discover Trustpoint via mDNS. '
                    'This is an additional component that needs to be deployed as a separate Docker container. '
                    'A ready-to-use Docker Compose file is provided in the Trustpoint repository: '
                    'docker-compose.mdns.yml '
                    '(https://github.com/Trustpoint-Project/trustpoint/blob/main/docker-compose.mdns.yml). '
                    'Note: this does not work with Docker Desktop.',
                    ValueRenderType.PLAIN,
                ),
            ],
        )


        how_it_works = HelpSection(
            _non_lazy('How AOKI with EST Works'),
            [
                HelpRow(
                    _non_lazy('Step 1: Device Discovery'),
                    '1. Device boots and sends mDNS query to discover Trustpoint server\n'
                    '2. Device receives server address and EST endpoint',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Step 2: Secure Connection via mTLS'),
                    '3. Device establishes TLS connection with IDevID certificate (mTLS)\n'
                    '4. Server validates IDevID certificate chain\n'
                    '5. Server verifies IDevID against manufacturer database',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Step 3: Certificate Issuance'),
                    '6. Device receives operational certificate from server\n'
                    '7. Automatic enrollment of application certificates',
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('Step 4: Device Verification'),
                    '8. Device verifies the signature of the DevOwnerID and its validity for the IDevID',
                    ValueRenderType.PLAIN,
                ),
            ],
        )

        aoki_init_cmd = AokiEstIDevIDCommandBuilder.get_aoki_init_command(help_context.host_base)
        aoki_response = AokiEstIDevIDCommandBuilder.get_aoki_init_response_example()
        keygen_cmd = AokiEstIDevIDCommandBuilder.get_keygen_command()
        csr_cmd = AokiEstIDevIDCommandBuilder.get_csr_command()
        enroll_path = f'{help_context.host_est_path}/.well-known/est/domain/domain_credential/simpleenroll'
        curl_cmd = AokiEstIDevIDCommandBuilder.get_curl_enroll_command(enroll_path)

        aoki_response_html = (
            f'<pre class="bg-body-secondary text-body p-3 rounded overflow-x-auto">'
            f'<code class="language-json">{aoki_response}</code></pre>'
        )

        example_commands = HelpSection(
            _non_lazy('Example Commands'),
            [
                HelpRow(
                    _non_lazy('Step 1: AOKI Initialization Request'),
                    aoki_init_cmd,
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Step 1a: Expected AOKI Init Response'),
                    aoki_response_html,
                    ValueRenderType.HTML,
                ),
                HelpRow(
                    _non_lazy('Step 2: Generate Key Pair for Domain Credential'),
                    keygen_cmd,
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Step 3: Create Certificate Signing Request (CSR)'),
                    csr_cmd,
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Step 4: Send Enrollment Request via curl'),
                    curl_cmd,
                    ValueRenderType.CODE,
                ),
            ],
        )

        return (
            [device_requirements, trustpoint_requirements, how_it_works, example_commands],
            _non_lazy('AOKI with EST - IDevID Authentication (mTLS)'),
        )


class AokiCmpHelpView(PageContextMixin, TemplateView):
    """Help view for AOKI with CMP (IDevID authentication)."""

    template_name = 'help/help_page.html'
    http_method_names = ('get',)

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_ZERO_TOUCH_SUBCATEGORY

    def _make_context(self, host_ip: str = '127.0.0.1') -> HelpContext:
        """Build generic context for AOKI help."""
        from pki.models import DomainModel  # noqa: PLC0415

        # HelpContext needs a domain per default. For demonstration purpose we take the first one

        try:
            domain = DomainModel.objects.first()
            if not domain:
                raise Http404(_('No domains configured in the system.'))
        except DomainModel.DoesNotExist as exc:
            raise Http404(_('No domains configured in the system.')) from exc

        host_base = f'https://{host_ip}:{self.request.META.get("SERVER_PORT", "443")}'

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        allowed_app_profiles = list(
            domain.get_allowed_cert_profiles().exclude(certificate_profile__unique_name='domain_credential'))

        return HelpContext(
            device=None,
            domain=domain,
            domain_unique_name=domain.unique_name,
            allowed_app_profiles=allowed_app_profiles,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/.aoki/initialization',
            host_est_path=f'{host_base}/.aoki/init',
            cred_count=0,
        )

    @override
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build context with AOKI CMP help page."""
        context = super().get_context_data(**kwargs)

        host_ip = self.request.GET.get('host_ip', '127.0.0.1')

        sections: list[HelpSection] = []
        heading = _non_lazy('AOKI with CMP - IDevID Authentication')

        try:
            help_context = self._make_context(host_ip=host_ip)
            strategy = AokiCmpIDevIDStrategy()
            sections, heading = strategy.build_sections(help_context)
        except Http404:
            sections.append(
                HelpSection(
                    _non_lazy('Prerequisites'),
                    [
                        HelpRow(
                            _non_lazy('No Domain Configured'),
                            'No domain is configured in Trustpoint yet. '
                            'Use the Demo Environment Setup section below to automatically '
                            'set up a test environment, or configure a domain manually first.',
                            ValueRenderType.PLAIN,
                        ),
                    ],
                )
            )

        sections.append(_build_aoki_demo_section(self.request))

        context['help_page'] = HelpPage(heading=heading, sections=sections)
        context['form'] = IpAddressForm(ip_choices=['127.0.0.1'], initial={'host_ip': host_ip})
        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value
        context['ValueRenderType_HTML'] = ValueRenderType.HTML.value

        return context


class AokiEstHelpView(PageContextMixin, TemplateView):
    """Help view for AOKI with EST (IDevID authentication)."""

    template_name = 'help/help_page.html'
    http_method_names = ('get',)

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_ZERO_TOUCH_SUBCATEGORY

    def _make_context(self, host_ip: str = '127.0.0.1') -> HelpContext:
        """Build generic context for AOKI help."""
        from pki.models import DomainModel  # noqa: PLC0415

        # HelpContext needs a domain per default. For demonstration purpose we take the first one

        try:
            domain = DomainModel.objects.first()
            if not domain:
                raise Http404(_('No domains configured in the system.'))
        except DomainModel.DoesNotExist as exc:
            raise Http404(_('No domains configured in the system.')) from exc

        host_base = f'https://{host_ip}:{self.request.META.get("SERVER_PORT", "443")}'

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        allowed_app_profiles = list(
            domain.get_allowed_cert_profiles().exclude(certificate_profile__unique_name='domain_credential'))

        return HelpContext(
            device=None,
            domain=domain,
            domain_unique_name=domain.unique_name,
            allowed_app_profiles=allowed_app_profiles,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.aoki/initialization',
            host_est_path=f'{host_base}',
            cred_count=0,
        )

    @override
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build context with AOKI EST help page."""
        context = super().get_context_data(**kwargs)

        host_ip = self.request.GET.get('host_ip', '127.0.0.1')

        sections: list[HelpSection] = []
        heading = _non_lazy('AOKI with EST - IDevID Authentication (mTLS)')

        try:
            help_context = self._make_context(host_ip=host_ip)
            strategy = AokiEstIDevIDStrategy()
            sections, heading = strategy.build_sections(help_context)
        except Http404:
            sections.append(
                HelpSection(
                    _non_lazy('Prerequisites'),
                    [
                        HelpRow(
                            _non_lazy('No Domain Configured'),
                            'No domain is configured in Trustpoint yet. '
                            'Use the Demo Environment Setup section below to automatically '
                            'set up a test environment, or configure a domain manually first.',
                            ValueRenderType.PLAIN,
                        ),
                    ],
                )
            )

        sections.append(_build_aoki_demo_section(self.request))

        context['help_page'] = HelpPage(heading=heading, sections=sections)
        context['form'] = IpAddressForm(ip_choices=['127.0.0.1'], initial={'host_ip': host_ip})
        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value
        context['ValueRenderType_HTML'] = ValueRenderType.HTML.value

        return context



_AOKI_DEMO_CERT_FILES: list[tuple[str, str]] = [
    ('idevid.pem', 'IDevID Certificate'),
    ('idevid_pk.pem', 'IDevID Private Key'),
    ('idevid_ca.pem', 'IDevID CA Certificate'),
    ('owner_id.pem', 'DevOwnerID Certificate'),
    ('owner_id_pk.pem', 'DevOwnerID Private Key'),
    ('ownerid_ca.pem', 'Owner CA Certificate'),
]

_AOKI_DEMO_CERTS_DIR: Path = (
    Path(__file__).resolve().parents[1] / 'aoki' / 'tests' / 'certs'
)

_AOKI_DEMO_ALLOWED_FILES: frozenset[str] = frozenset(name for name, _ in _AOKI_DEMO_CERT_FILES)


def _build_aoki_demo_section(request: Any) -> HelpSection:
    """Build the *Demo Environment Setup* help section for the AOKI help pages."""
    del request
    setup_url = reverse('devices:zero_touch_credentials-aoki_setup_demo_env')
    download_base_url = reverse(
        'devices:zero_touch_credentials-aoki_demo_download',
        kwargs={'filename': 'placeholder'},
    ).replace('placeholder', '')

    download_buttons_html = ''
    for filename, label in _AOKI_DEMO_CERT_FILES:
        file_path = _AOKI_DEMO_CERTS_DIR / filename
        if file_path.exists():
            download_buttons_html += (
                f'<a href="{download_base_url}{filename}" '
                f'class="btn btn-sm btn-outline-secondary me-2 mb-2" download="{filename}">'
                f'\u2b07 {label} ({filename})</a>'
            )
        else:
            download_buttons_html += (
                f'<span class="btn btn-sm btn-outline-secondary me-2 mb-2 disabled" '
                f'title="Run setup first">'
                f'\u2b07 {label} ({filename})</span>'
            )

    setup_html = SafeString(
        f'<form method="post" action="{setup_url}" style="display:inline;">'
        f'CSRF_TOKEN_PLACEHOLDER'
        f'<button type="submit" class="btn btn-primary mb-3">'
        f'Run aoki_setup_idevid_test_env</button>'
        f'</form>'
        f'<div class="mt-2">{download_buttons_html}</div>'
    )

    return HelpSection(
        _non_lazy('Demo Environment Setup'),
        [
            HelpRow(
                _non_lazy('Setup'),
                'Click the button below to generate a test IDevID PKI and DevOwnerID credential and '
                'register them in Trustpoint automatically. Afterwards, download the '
                'generated certificate and key files to use them with your AOKI client.',
                ValueRenderType.PLAIN,
            ),
            HelpRow(
                _non_lazy('Actions'),
                setup_html,
                ValueRenderType.HTML,
            ),
        ],
    )


class AokiSetupDemoEnvView(PageContextMixin, View):
    """POST view that runs the ``aoki_setup_idevid_test_env`` management command."""

    http_method_names = ('post',)

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_ZERO_TOUCH_SUBCATEGORY

    def post(self, request: Any, *args: Any, **kwargs: Any) -> HttpResponseRedirect:
        """Run setup command and redirect back."""
        del args, kwargs
        try:
            call_command('aoki_setup_idevid_test_env')
            messages.success(
                request,
                'AOKI demo environment set up successfully. '
                'You can now download the generated certificate and key files.',
            )
        except Exception as exc:  # noqa: BLE001
            messages.error(request, f'Setup failed: {exc}')

        referer = request.META.get('HTTP_REFERER', '')
        cmp_url = reverse('devices:zero_touch_credentials-aoki_cmp_help')
        est_url = reverse('devices:zero_touch_credentials-aoki_est_help')
        if referer.endswith(est_url):
            return HttpResponseRedirect(est_url)
        return HttpResponseRedirect(cmp_url)


class AokiDemoDownloadView(PageContextMixin, View):
    """Serve a single file from the AOKI demo certificate directory for download."""

    http_method_names = ('get',)

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_ZERO_TOUCH_SUBCATEGORY

    def get(self, request: Any, filename: str, *args: Any, **kwargs: Any) -> FileResponse:
        """Stream the requested certificate / key file."""
        del request, args, kwargs
        if filename not in _AOKI_DEMO_ALLOWED_FILES:
            raise Http404
        file_path = _AOKI_DEMO_CERTS_DIR / filename
        if not file_path.exists():
            raise Http404
        return FileResponse(
            file_path.open('rb'),
            as_attachment=True,
            filename=filename,
        )
