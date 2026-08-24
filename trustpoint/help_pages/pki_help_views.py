# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""This module contains all views concerning the help pages used within the pki app."""

from __future__ import annotations

from typing import Any

from django.http import Http404
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext as _non_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic.detail import DetailView

from devices.views import PublicKeyInfoMissingErrorMsg
from help_pages.base import (
    HelpContext,
    HelpPageStrategy,
    build_extract_files_from_p12_section,
    build_issuing_ca_cert_section,
    build_keygen_section,
    build_tls_trust_store_section,
)
from help_pages.help_section import HelpPage, HelpRow, HelpSection, ValueRenderType
from management.models import TlsSettings
from pki.models import CaModel, DevIdRegistration, DomainModel, IssuedCredentialModel, OwnerCredentialModel

PKI_PAGE_DOMAIN_SUBCATEGORY = 'pki:domain'
PKI_PAGE_TRUSTSTORES_SUBCATEGORY = 'pki:truststores'


class BaseHelpView(DetailView[DevIdRegistration]):
    """Base help view for PKI help pages."""

    template_name = 'help/help_page.html'
    model = DevIdRegistration
    context_object_name = 'devid_registration'

    page_category = 'pki'
    page_name: str
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        devid_registration = self.object
        domain = getattr(devid_registration, 'domain', None)
        if not domain:
            raise Http404(_('Failed to get domain from DevidRegistration.'))

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            devid_registration=devid_registration,
            allowed_app_profiles=[],
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the help page."""
        context = super().get_context_data(**kwargs)
        help_context = self._make_context()
        sections, heading = self.strategy.build_sections(help_context)
        context['help_page'] = HelpPage(heading=heading, sections=sections)
        context['ValueRenderType_CODE'] = ValueRenderType.CODE.value
        context['back_url'] = 'pki:domains-config'
        return context


class OnboardingCmpIdevIdDomainCredentialStrategy(HelpPageStrategy):
    """Strategy for CMP onboarding with IDevID domain credential."""

    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        """Build sections for CMP onboarding help page."""
        domain = help_context.domain
        if domain is None:
            err_msg = 'Domain is required for CMP onboarding'
            raise ValueError(err_msg)

        summary_section = HelpSection(
            heading=str(_('Summary')),
            rows=[
                HelpRow(
                    key=_non_lazy('Protocol'),
                    value=_non_lazy('CMP'),
                    value_render_type=ValueRenderType.PLAIN,
                ),
                HelpRow(
                    key=_non_lazy('Authentication'),
                    value=_non_lazy('IDevID with Domain Credential'),
                    value_render_type=ValueRenderType.PLAIN,
                ),
            ],
        )

        keygen_section = build_keygen_section(
            help_context=help_context,
            file_name='idevid',
        )

        issuing_ca_section = build_issuing_ca_cert_section(domain=domain)

        extract_section = build_extract_files_from_p12_section()

        return (
            [summary_section, keygen_section, issuing_ca_section, extract_section],
            'Help - Issue Application Certificates',
        )


class OnboardingEstIdevIdDomainCredentialStrategy(HelpPageStrategy):
    """Strategy for EST onboarding with IDevID domain credential."""

    def build_sections(self, help_context: HelpContext) -> tuple[list[HelpSection], str]:
        """Build sections for EST onboarding help page."""
        summary_section = HelpSection(
            heading=str(_('Summary')),
            rows=[
                HelpRow(
                    key=_non_lazy('Protocol'),
                    value=_non_lazy('EST'),
                    value_render_type=ValueRenderType.PLAIN,
                ),
                HelpRow(
                    key=_non_lazy('Authentication'),
                    value=_non_lazy('IDevID with Domain Credential'),
                    value_render_type=ValueRenderType.PLAIN,
                ),
            ],
        )

        keygen_section = build_keygen_section(
            help_context=help_context,
            file_name='idevid',
        )

        tls_section = build_tls_trust_store_section()

        extract_section = build_extract_files_from_p12_section()

        return [summary_section, keygen_section, tls_section, extract_section], 'Help - Issue Application Certificates'


class OnboardingCmpIdevidRegistrationHelpView(BaseHelpView):
    """Help view for CMP onboarding with IDevID domain credential."""

    page_name = 'domains'
    strategy = OnboardingCmpIdevIdDomainCredentialStrategy()


class OnboardingEstIdevidRegistrationHelpView(BaseHelpView):
    """Help view for EST onboarding with IDevID domain credential."""

    page_name = 'domains'
    strategy = OnboardingEstIdevIdDomainCredentialStrategy()


class DevIdRegistrationDetailView(DetailView[DevIdRegistration]):
    """View to display details of a DevIdRegistration."""

    model = DevIdRegistration
    template_name = 'help/devid_registration_detail.html'
    context_object_name = 'devid_registration'

    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        devid_registration = self.object
        domain = getattr(devid_registration, 'domain', None)
        if not domain:
            raise Http404(_('Failed to get domain from DevidRegistration.'))

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            devid_registration=devid_registration,
            allowed_app_profiles=[],  # not required for IDevID help views
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[],
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the DevIdRegistration detail view."""
        context = super().get_context_data(**kwargs)
        help_context = self._make_context()
        context.update(
            {
                'page_name': help_context.page_name,
                'domain': help_context.domain,
                'domain_unique_name': help_context.domain_unique_name,
                'public_key_info': help_context.public_key_info,
                'host_base': help_context.host_base,
                'help_sections': help_context.help_sections,
            }
        )
        return context


class DevIdRegistrationHelpView(DevIdRegistrationDetailView):
    """View to display help pages for DevIdRegistration."""

    template_name = 'help/help_page.html'
    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY

    def _make_context(self) -> HelpContext:
        devid_registration = self.object
        domain = getattr(devid_registration, 'domain', None)
        if not domain:
            raise Http404(_('Failed to get domain from DevidRegistration.'))

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        help_context = HelpContext(
            devid_registration=devid_registration,
            allowed_app_profiles=[],
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
        )

        keygen_section = build_keygen_section(
            help_context=help_context,
            file_name='idevid',
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(domain=domain)

        tls_trust_store_section = build_tls_trust_store_section()

        return HelpContext(
            devid_registration=devid_registration,
            allowed_app_profiles=[],
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[
                keygen_section,
                issuing_ca_cert_section,
                tls_trust_store_section,
            ],
        )


class DomainDetailView(DetailView[DomainModel]):
    """View to display details of a Domain."""

    model = DomainModel
    template_name = 'help/domain_detail.html'
    context_object_name = 'domain'

    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        domain = self.object

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            allowed_app_profiles=list(domain.get_allowed_cert_profiles()),
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[],
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the Domain detail view."""
        context = super().get_context_data(**kwargs)
        help_context = self._make_context()
        context.update(
            {
                'page_name': help_context.page_name,
                'domain': help_context.domain,
                'domain_unique_name': help_context.domain_unique_name,
                'public_key_info': help_context.public_key_info,
                'host_base': help_context.host_base,
                'help_sections': help_context.help_sections,
                'allowed_app_profiles': help_context.allowed_app_profiles,
            }
        )
        return context


class DomainHelpView(DomainDetailView):
    """View to display help pages for Domain."""

    template_name = 'help/help_page.html'
    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY

    def _make_context(self) -> HelpContext:
        domain = self.object

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        help_context = HelpContext(
            allowed_app_profiles=list(domain.get_allowed_cert_profiles()),
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
        )

        keygen_section = build_keygen_section(
            help_context=help_context,
            file_name='app_cert',
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(domain=domain)

        tls_trust_store_section = build_tls_trust_store_section()

        return HelpContext(
            allowed_app_profiles=list(domain.get_allowed_cert_profiles()),
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[
                keygen_section,
                issuing_ca_cert_section,
                tls_trust_store_section,
            ],
        )


class IssuedCredentialDetailView(DetailView[IssuedCredentialModel]):
    """View to display details of an IssuedCredential."""

    model = IssuedCredentialModel
    template_name = 'help/issued_credential_detail.html'
    context_object_name = 'issued_credential'

    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        issued_credential = self.object
        device = getattr(issued_credential, 'device', None)
        if not device:
            raise Http404(_('Failed to get device from IssuedCredential.'))

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = device.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            device=device,
            issued_credential=issued_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{device.domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{device.domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[],
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the IssuedCredential detail view."""
        context = super().get_context_data(**kwargs)
        help_context = self._make_context()
        context.update(
            {
                'page_name': help_context.page_name,
                'device': help_context.device,
                'issued_credential': help_context.issued_credential,
                'domain': help_context.domain,
                'domain_unique_name': help_context.domain_unique_name,
                'public_key_info': help_context.public_key_info,
                'host_base': help_context.host_base,
                'help_sections': help_context.help_sections,
            }
        )
        return context


class IssuedCredentialHelpView(IssuedCredentialDetailView):
    """View to display help pages for IssuedCredential."""

    template_name = 'help/help_page.html'
    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY

    def _make_context(self) -> HelpContext:
        issued_credential = self.object
        device = getattr(issued_credential, 'device', None)
        if not device:
            raise Http404(_('Failed to get device from IssuedCredential.'))

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = device.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        help_context = HelpContext(
            device=device,
            issued_credential=issued_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{device.domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{device.domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
        )

        keygen_section = build_keygen_section(
            help_context=help_context,
            file_name='app_cert',
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(domain=device.domain)

        tls_trust_store_section = build_tls_trust_store_section()

        return HelpContext(
            device=device,
            issued_credential=issued_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{device.domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{device.domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[
                keygen_section,
                issuing_ca_cert_section,
                tls_trust_store_section,
            ],
        )


class OwnerCredentialDetailView(DetailView[OwnerCredentialModel]):
    """View to display details of an OwnerCredential."""

    model = OwnerCredentialModel
    template_name = 'help/owner_credential_detail.html'
    context_object_name = 'owner_credential'

    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        owner_credential = self.object
        device = getattr(owner_credential, 'device', None)
        if not device:
            raise Http404(_('Failed to get device from OwnerCredential.'))

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = device.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            device=device,
            owner_credential=owner_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{device.domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{device.domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[],
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the OwnerCredential detail view."""
        context = super().get_context_data(**kwargs)
        help_context = self._make_context()
        context.update(
            {
                'page_name': help_context.page_name,
                'device': help_context.device,
                'owner_credential': help_context.owner_credential,
                'domain': help_context.domain,
                'domain_unique_name': help_context.domain_unique_name,
                'public_key_info': help_context.public_key_info,
                'host_base': help_context.host_base,
                'help_sections': help_context.help_sections,
            }
        )
        return context


class OwnerCredentialHelpView(OwnerCredentialDetailView):
    """View to display help pages for OwnerCredential."""

    template_name = 'help/help_page.html'
    page_name = PKI_PAGE_DOMAIN_SUBCATEGORY

    def _make_context(self) -> HelpContext:
        owner_credential = self.object
        device = getattr(owner_credential, 'device', None)
        if not device:
            raise Http404(_('Failed to get device from OwnerCredential.'))

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        public_key_info = device.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        help_context = HelpContext(
            device=device,
            owner_credential=owner_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{device.domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{device.domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
        )

        keygen_section = build_keygen_section(
            help_context=help_context,
            file_name='owner_cert',
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(domain=device.domain)

        tls_trust_store_section = build_tls_trust_store_section()

        return HelpContext(
            device=device,
            owner_credential=owner_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            host_cmp_path=f'{host_base}/.well-known/cmp/p/{device.domain.unique_name}',
            host_est_path=f'{host_base}/.well-known/est/{device.domain.unique_name}',
            cred_count=0,
            page_name=self.page_name,
            help_sections=[
                keygen_section,
                issuing_ca_cert_section,
                tls_trust_store_section,
            ],
        )


class CaDetailView(DetailView[CaModel]):
    """View to display details of a CA."""

    model = CaModel
    template_name = 'help/ca_detail.html'
    context_object_name = 'ca'

    page_name = PKI_PAGE_TRUSTSTORES_SUBCATEGORY
    strategy: HelpPageStrategy

    def _make_context(self) -> HelpContext:
        ca = self.object

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        # Create a minimal HelpContext for CA views
        # CA views don't need domain/public_key_info, but HelpContext requires them
        # We'll use placeholder values
        return HelpContext(
            ca=ca,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[],
            domain=None,
            domain_unique_name='',
            allowed_app_profiles=[],
            public_key_info=None,
            host_cmp_path='',
            host_est_path='',
            cred_count=0,
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data for the CA detail view."""
        context = super().get_context_data(**kwargs)
        help_context = self._make_context()
        context.update(
            {
                'page_name': help_context.page_name,
                'ca': help_context.ca,
                'host_base': help_context.host_base,
                'help_sections': help_context.help_sections,
            }
        )
        return context


class CaHelpView(CaDetailView):
    """View to display help pages for CA."""

    template_name = 'help/help_page.html'
    page_name = PKI_PAGE_TRUSTSTORES_SUBCATEGORY

    def _make_context(self) -> HelpContext:
        ca = self.object

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )

        ca_cert_section = HelpSection(
            heading=_non_lazy('CA Certificate'),
            rows=[
                HelpRow(
                    key=_non_lazy('CA Certificate'),
                    value=format_html(
                        '<a href="{}">Download CA Certificate (PEM)</a>',
                        reverse('pki:ca-cert-download', kwargs={'pk': ca.pk}),
                    ),
                    value_render_type=ValueRenderType.HTML,
                ),
                HelpRow(
                    key=_non_lazy('CA Certificate Chain'),
                    value=format_html(
                        '<a href="{}">Download CA Certificate Chain (PEM)</a>',
                        reverse('pki:ca-cert-chain-download', kwargs={'pk': ca.pk}),
                    ),
                    value_render_type=ValueRenderType.HTML,
                ),
            ],
        )

        return HelpContext(
            ca=ca,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[ca_cert_section],
            domain=None,
            domain_unique_name='',
            allowed_app_profiles=[],
            public_key_info=None,
            host_cmp_path='',
            host_est_path='',
            cred_count=0,
        )


class CrlDownloadHelpView(CaDetailView):
    """View to display help pages for CRL download."""

    template_name = 'help/help_page.html'
    page_name = PKI_PAGE_TRUSTSTORES_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data and builds the HelpPage for CRL download."""
        context = super().get_context_data(**kwargs)
        ca = self.object

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", "443")}'
        )
        crl_endpoint = f'{host_base}/crl/{ca.pk}/'

        has_crl = bool(ca.crl_pem)
        crl_status_rows = []

        if has_crl and ca.last_crl_issued_at:
            crl_status_rows.append(
                HelpRow(
                    key=_non_lazy('CRL Status'),
                    value=_non_lazy('Available'),
                    value_render_type=ValueRenderType.PLAIN,
                )
            )
            crl_status_rows.append(
                HelpRow(
                    key=_non_lazy('Last CRL Issued At'),
                    value=ca.last_crl_issued_at.isoformat(),
                    value_render_type=ValueRenderType.PLAIN,
                )
            )
            crl_status_rows.append(
                HelpRow(
                    key=_non_lazy('CRL Download'),
                    value=format_html(
                        '<a href="{}">Download CRL (PEM)</a>',
                        reverse('pki:ca-crl-download', kwargs={'pk': ca.pk}),
                    ),
                    value_render_type=ValueRenderType.HTML,
                )
            )
        else:
            crl_status_rows.append(
                HelpRow(
                    key=_non_lazy('CRL Status'),
                    value=_non_lazy('Not Available'),
                    value_render_type=ValueRenderType.PLAIN,
                )
            )

        context['help_sections'] = [
            HelpSection(
                heading=_non_lazy('CRL Status'),
                rows=crl_status_rows,
            ),
        ]
        context['host_base'] = host_base
        context['crl_endpoint'] = crl_endpoint

        return context
