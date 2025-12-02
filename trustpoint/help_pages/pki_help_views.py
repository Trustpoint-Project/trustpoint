"""This module contains all views concerning the help pages used within the pki app."""

from __future__ import annotations

from typing import Any, override

from devices.views import PublicKeyInfoMissingErrorMsg
from django.http import Http404
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext as _non_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView
from management.models import TlsSettings
from pki.models import DevIdRegistration, IssuingCaModel
from trustpoint.page_context import (
    PKI_PAGE_CATEGORY,
    PKI_PAGE_DOMAIN_SUBCATEGORY,
    PKI_PAGE_ISSUING_CAS_SUBCATEGORY,
    PageContextMixin,
)

from help_pages.base import (
    ApplicationCertificateProfile,
    HelpContext,
    HelpPageStrategy,
    build_extract_files_from_p12_section,
    build_issuing_ca_cert_section,
    build_keygen_section,
    build_tls_trust_store_section,
)
from help_pages.commands import (
    CmpClientCertificateCommandBuilder,
    EstClientCertificateCommandBuilder,
)
from help_pages.help_section import HelpPage, HelpRow, HelpSection, ValueRenderType

# --------------------------------------------------- Base Classes ----------------------------------------------------


class BaseHelpView(PageContextMixin, DetailView[DevIdRegistration]):
    """Base help view that constructs the context."""

    template_name = 'help/help_page.html'
    http_method_names = ('get',)
    model = DevIdRegistration
    context_object_name = 'idevid_registration'

    page_category = PKI_PAGE_CATEGORY
    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        devid_registration = self.object
        domain = getattr(devid_registration, 'domain', None)
        if not domain:
            raise Http404(_('Failed to get domain from DevidRegistration.'))

        host_base = f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}'

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            devid_registration=devid_registration,
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
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
        context['back_url'] = f'{self.page_category}:{self.page_name}-config'

        return context


# ------------------------- Onboarding - Application Certificates - Help Page Implementations -------------------------


class OnboardingCmpIdevIdDomainCredentialStrategy(HelpPageStrategy):
    """Strategy for building the onboarding cmp shared-secret help page."""

    _allowed_app_cert_profiles: list[ApplicationCertificateProfile]

    def __init__(self, allowed_app_cert_profiles: list[ApplicationCertificateProfile]) -> None:
        """Inits the object by setting the allowed app cert profiles.

        Args:
            allowed_app_cert_profiles: List of allowed application certificate profiles.
        """
        self._allowed_app_cert_profiles = allowed_app_cert_profiles

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        operation = 'initialization'
        base = help_context.host_cmp_path

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Domain Credential Request URL'),
                    f'{base}/{operation}',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
            ],
        )

        enroll_cmd = CmpClientCertificateCommandBuilder.get_idevid_domain_credential_command(
            host=f'{base}/domain_credential/{operation}'
        )

        enroll_row = HelpRow(
            _non_lazy('Enroll the Domain Credential with CMP'), value=enroll_cmd, value_render_type=ValueRenderType.CODE
        )

        enroll_section = HelpSection(heading=_non_lazy('Enroll Domain Credential'), rows=[enroll_row])
        sections = [
            summary,
            build_issuing_ca_cert_section(domain=help_context.domain),
            build_keygen_section(help_context, file_name='domain-credential-key.pem'),
            build_extract_files_from_p12_section(),
            enroll_section,
        ]

        return sections, _non_lazy('Help - Issue Application Certificates using CMP with a Domain Credential')


class OnboardingCmpIdevidRegistrationHelpView(BaseHelpView):
    """Help view for the CMP IDevID Registration, which displays the required OpenSSL commands."""

    strategy = OnboardingCmpIdevIdDomainCredentialStrategy(
        allowed_app_cert_profiles=list(ApplicationCertificateProfile)
    )


class OnboardingEstIdevIdDomainCredentialStrategy(HelpPageStrategy):
    """Strategy for building the onboarding cmp shared-secret help page."""

    _allowed_app_cert_profiles: list[ApplicationCertificateProfile]

    def __init__(self, allowed_app_cert_profiles: list[ApplicationCertificateProfile]) -> None:
        """Inits the object by setting the allowed app cert profiles.

        Args:
            allowed_app_cert_profiles: List of allowed application certificate profiles.
        """
        self._allowed_app_cert_profiles = allowed_app_cert_profiles

    @override
    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        operation = 'simpleenroll'
        base = help_context.host_cmp_path

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Domain Credential Request URL'),
                    f'{base}/{operation}',
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Required Public Key Type'),
                    str(help_context.domain.public_key_info),
                    ValueRenderType.CODE,
                ),
            ],
        )

        gen_csr_row = HelpRow(
            _non_lazy('Domain Credential CSR Generation'),
            value=EstClientCertificateCommandBuilder.get_idevid_gen_csr_command(),
            value_render_type=ValueRenderType.CODE,
        )

        enroll_row = HelpRow(
            _non_lazy('Enroll the Domain Credential with EST'),
            value=EstClientCertificateCommandBuilder.get_idevid_enroll_domain_credential_command(
                host=f'{base}/domain_credential/{operation}'
            ),
            value_render_type=ValueRenderType.CODE,
        )

        der_pem_conversion_row = HelpRow(
            _non_lazy('Convert DER to PEM'),
            value=EstClientCertificateCommandBuilder.get_idevid_der_pem_conversion_command(),
            value_render_type=ValueRenderType.CODE,
        )

        enroll_section = HelpSection(
            heading=_non_lazy('Enroll Domain Credential'), rows=[gen_csr_row, enroll_row, der_pem_conversion_row]
        )

        get_ca_certs_row = HelpRow(
            _non_lazy('Retrieve CA chain'),
            value=EstClientCertificateCommandBuilder.get_idevid_ca_certs_command(host=f'{base}/cacerts/'),
            value_render_type=ValueRenderType.CODE,
        )

        pkcs7_pem_conversion_row = HelpRow(
            _non_lazy('Convert PKCS7 to PEM'),
            value=EstClientCertificateCommandBuilder.get_idevid_pkcs7_pem_conversion_command(),
            value_render_type=ValueRenderType.CODE,
        )

        ca_cert_section = HelpSection(
            heading=_non_lazy('CA Certificate Chain'),
            rows=[
                get_ca_certs_row,
                pkcs7_pem_conversion_row,
            ],
        )

        sections = [
            summary,
            build_tls_trust_store_section(),
            build_keygen_section(help_context, file_name='domain-credential-key.pem'),
            build_extract_files_from_p12_section(),
            enroll_section,
            ca_cert_section,
        ]

        return sections, _non_lazy('Help - Issue Application Certificates using CMP with a Domain Credential')


class OnboardingEstIdevidRegistrationHelpView(BaseHelpView):
    """Help view for the EST IDevID Registration, which displays the required OpenSSL commands."""

    strategy = OnboardingEstIdevIdDomainCredentialStrategy(
        allowed_app_cert_profiles=list(ApplicationCertificateProfile)
    )


# ------------------------------------------ CRL Download Help Page ---------------------------------------------------


class CrlDownloadHelpView(PageContextMixin, DetailView[IssuingCaModel]):
    """Help view for downloading CRLs via curl commands."""

    template_name = 'help/help_page.html'
    http_method_names = ('get',)
    model = IssuingCaModel
    context_object_name = 'issuing_ca'

    page_category = PKI_PAGE_CATEGORY
    page_name = PKI_PAGE_ISSUING_CAS_SUBCATEGORY

    @override
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data and builds the HelpPage for CRL download."""
        context = super().get_context_data(**kwargs)
        issuing_ca = self.object

        host_base = f'https://{TlsSettings.get_first_ipv4_address()}:{self.request.META.get("SERVER_PORT", "443")}'
        crl_endpoint = f'{host_base}/crl/{issuing_ca.pk}/'

        has_crl = bool(issuing_ca.crl_pem)
        crl_status_rows = []

        if has_crl and issuing_ca.last_crl_issued_at:
            crl_status_rows.append(
                HelpRow(
                    _non_lazy('CRL Status'),
                    _non_lazy('Available'),
                    ValueRenderType.PLAIN,
                )
            )
            crl_status_rows.append(
                HelpRow(
                    _non_lazy('Last Generated'),
                    issuing_ca.last_crl_issued_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    ValueRenderType.PLAIN,
                )
            )
        else:
            crl_status_rows.append(
                HelpRow(
                    _non_lazy('CRL Status'),
                    _non_lazy('Not Available - Generate a CRL first'),
                    ValueRenderType.PLAIN,
                )
            )

        help_page_url = reverse('pki:help_issuing_cas_crl_download', kwargs={'pk': issuing_ca.pk})
        generate_url = reverse('pki:issuing_cas-crl-gen', kwargs={'pk': issuing_ca.pk})
        generate_url_with_next = f'{generate_url}?next={help_page_url}'
        generate_button = format_html(
            '<a href="{}" class="btn btn-primary w-100">{}</a>',
            generate_url_with_next,
            _non_lazy('Generate CRL')
        )
        crl_status_rows.append(
            HelpRow(
                _non_lazy('Generate New CRL'),
                generate_button,
                ValueRenderType.PLAIN,
            )
        )

        crl_status_section = HelpSection(_non_lazy('CRL Status'), crl_status_rows)

        summary = HelpSection(
            _non_lazy('Summary'),
            [
                HelpRow(
                    _non_lazy('Issuing CA'),
                    issuing_ca.unique_name,
                    ValueRenderType.PLAIN,
                ),
                HelpRow(
                    _non_lazy('CRL Download Endpoint'),
                    crl_endpoint,
                    ValueRenderType.CODE,
                ),
            ],
        )

        download_pem_cmd = (
            f'curl --cacert trustpoint-tls-trust-store.pem \\\n'
            f'  -o {issuing_ca.unique_name}.crl \\\n'
            f'  "{crl_endpoint}"'
        )

        download_der_cmd = (
            f'curl --cacert trustpoint-tls-trust-store.pem \\\n'
            f'  -o {issuing_ca.unique_name}.crl \\\n'
            f'  "{crl_endpoint}?encoding=der"'
        )

        download_section = HelpSection(
            _non_lazy('Download CRL'),
            [
                HelpRow(
                    _non_lazy('Download CRL in PEM Format'),
                    download_pem_cmd,
                    ValueRenderType.CODE,
                ),
                HelpRow(
                    _non_lazy('Download CRL in DER Format'),
                    download_der_cmd,
                    ValueRenderType.CODE,
                ),
            ],
        )

        notes_section = HelpSection(
            _non_lazy('Important Notes'),
            [
                HelpRow(
                    _non_lazy('Public Access'),
                    _non_lazy(
                        'This endpoint does not require authentication and can be accessed by any client '
                        'that needs to verify certificate revocation status.'
                    ),
                    ValueRenderType.PLAIN,
                ),
            ],
        )

        tls_trust_store_section = build_tls_trust_store_section()

        sections = [summary, crl_status_section, tls_trust_store_section, download_section, notes_section]

        context['help_page'] = HelpPage(
            heading=_non_lazy(f'Help - Download CRL for {issuing_ca.unique_name}'), sections=sections
        )
        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['ValueRenderType_PLAIN'] = ValueRenderType.PLAIN.value

        context['idevid_registration'] = type('obj', (object,), {
            'domain': type('obj', (object,), {'pk': issuing_ca.pk})()
        })()
        context['back_url'] = f'{self.page_category}:{self.page_name}-config'
        context['back_button_text'] = _non_lazy('Back to Issuing CA Configuration')

        return context
