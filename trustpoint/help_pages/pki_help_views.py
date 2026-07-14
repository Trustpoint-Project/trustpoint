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
    build_issuing_ca_cert_section,
    build_keygen_section,
    build_tls_trust_store_section,
)
from help_pages.help_section import HelpRow, HelpSection, ValueRenderType
from management.models import TlsSettings
from pki.models import CaModel, DevIdRegistration, DomainModel, IssuedCredentialModel, OwnerCredentialModel
from trustpoint.settings import ADVERTISED_PORT

PKI_PAGE_DOMAIN_SUBCATEGORY = 'pki:domain'
PKI_PAGE_TRUSTSTORES_SUBCATEGORY = 'pki:truststores'


class DevIdRegistrationDetailView(DetailView):
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        keygen_section = build_keygen_section(
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(
            domain=domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        tls_trust_store_section = build_tls_trust_store_section(
            domain=domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        return HelpContext(
            devid_registration=devid_registration,
            allowed_app_profiles=[],
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[
                HelpSection(
                    title=_('Key Generation'),
                    rows=keygen_section,
                ),
                HelpSection(
                    title=_('Issuing CA Certificate'),
                    rows=issuing_ca_cert_section,
                ),
                HelpSection(
                    title=_('TLS Trust Store'),
                    rows=tls_trust_store_section,
                ),
            ],
        )


class DomainDetailView(DetailView):
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        return HelpContext(
            allowed_app_profiles=domain.get_allowed_cert_profiles(),
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )

        public_key_info = domain.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        keygen_section = build_keygen_section(
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(
            domain=domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        tls_trust_store_section = build_tls_trust_store_section(
            domain=domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        return HelpContext(
            allowed_app_profiles=domain.get_allowed_cert_profiles(),
            domain=domain,
            domain_unique_name=domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[
                HelpSection(
                    title=_('Key Generation'),
                    rows=keygen_section,
                ),
                HelpSection(
                    title=_('Issuing CA Certificate'),
                    rows=issuing_ca_cert_section,
                ),
                HelpSection(
                    title=_('TLS Trust Store'),
                    rows=tls_trust_store_section,
                ),
            ],
        )


class IssuedCredentialDetailView(DetailView):
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )

        public_key_info = device.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        keygen_section = build_keygen_section(
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(
            domain=device.domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        tls_trust_store_section = build_tls_trust_store_section(
            domain=device.domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        return HelpContext(
            device=device,
            issued_credential=issued_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[
                HelpSection(
                    title=_('Key Generation'),
                    rows=keygen_section,
                ),
                HelpSection(
                    title=_('Issuing CA Certificate'),
                    rows=issuing_ca_cert_section,
                ),
                HelpSection(
                    title=_('TLS Trust Store'),
                    rows=tls_trust_store_section,
                ),
            ],
        )


class OwnerCredentialDetailView(DetailView):
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )

        public_key_info = device.public_key_info
        if not public_key_info:
            raise Http404(PublicKeyInfoMissingErrorMsg)

        keygen_section = build_keygen_section(
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
        )

        issuing_ca_cert_section = build_issuing_ca_cert_section(
            domain=device.domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        tls_trust_store_section = build_tls_trust_store_section(
            domain=device.domain,
            host_base=host_base,
            page_name=self.page_name,
        )

        return HelpContext(
            device=device,
            owner_credential=owner_credential,
            allowed_app_profiles=[],
            domain=device.domain,
            domain_unique_name=device.domain.unique_name,
            public_key_info=public_key_info,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[
                HelpSection(
                    title=_('Key Generation'),
                    rows=keygen_section,
                ),
                HelpSection(
                    title=_('Issuing CA Certificate'),
                    rows=issuing_ca_cert_section,
                ),
                HelpSection(
                    title=_('TLS Trust Store'),
                    rows=tls_trust_store_section,
                ),
            ],
        )


class CaDetailView(DetailView):
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )

        return HelpContext(
            ca=ca,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[],
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
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )

        ca_cert_section = [
            HelpRow(
                _non_lazy('CA Certificate'),
                _non_lazy('Download the CA certificate in PEM format.'),
                ValueRenderType.CODE,
                format_html(
                    '<a href="{}">Download CA Certificate (PEM)</a>',
                    reverse('pki:ca-cert-download', kwargs={'pk': ca.pk}),
                ),
            ),
            HelpRow(
                _non_lazy('CA Certificate Chain'),
                _non_lazy('Download the complete CA certificate chain in PEM format.'),
                ValueRenderType.CODE,
                format_html(
                    '<a href="{}">Download CA Certificate Chain (PEM)</a>',
                    reverse('pki:ca-cert-chain-download', kwargs={'pk': ca.pk}),
                ),
            ),
        ]

        return HelpContext(
            ca=ca,
            host_base=host_base,
            page_name=self.page_name,
            help_sections=[
                HelpSection(
                    title=_('CA Certificate'),
                    rows=ca_cert_section,
                ),
            ],
        )


class CrlHelpView(CaDetailView):
    """View to display help pages for CRL download."""

    template_name = 'help/help_page.html'
    page_name = PKI_PAGE_TRUSTSTORES_SUBCATEGORY

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Gets the context data and builds the HelpPage for CRL download."""
        context = super().get_context_data(**kwargs)
        ca = self.object

        host_base = (
            f'https://{TlsSettings.get_first_ipv4_address()}:'
            f'{self.request.META.get("HTTP_X_FORWARDED_PORT", ADVERTISED_PORT)}'
        )
        crl_endpoint = f'{host_base}/crl/{ca.pk}/'

        has_crl = bool(ca.crl_pem)
        crl_status_rows = []

        if has_crl and ca.last_crl_issued_at:
            crl_status_rows.append(
                HelpRow(
                    _non_lazy('CRL Status'),
                    _non_lazy('Available'),
                    ValueRenderType.TEXT,
                    _non_lazy('A CRL is available for download.'),
                )
            )
            crl_status_rows.append(
                HelpRow(
                    _non_lazy('Last CRL Issued At'),
                    _non_lazy('Timestamp'),
                    ValueRenderType.TEXT,
                    ca.last_crl_issued_at.isoformat(),
                )
            )
            crl_status_rows.append(
                HelpRow(
                    _non_lazy('CRL Download'),
                    _non_lazy('Download the CRL in PEM format.'),
                    ValueRenderType.CODE,
                    format_html(
                        '<a href="{}">Download CRL (PEM)</a>',
                        reverse('pki:ca-crl-download', kwargs={'pk': ca.pk}),
                    ),
                )
            )
        else:
            crl_status_rows.append(
                HelpRow(
                    _non_lazy('CRL Status'),
                    _non_lazy('Not Available'),
                    ValueRenderType.TEXT,
                    _non_lazy('No CRL is available for download.'),
                )
            )

        context['help_sections'] = [
            HelpSection(
                title=_('CRL Status'),
                rows=crl_status_rows,
            ),
        ]
        context['host_base'] = host_base
        context['crl_endpoint'] = crl_endpoint

        return context
