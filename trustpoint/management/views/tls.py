"""TLS setting specific views."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic import FormView, View, TemplateView
from pki.models import GeneralNameIpAddress
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel, CredentialModel, CertificateModel
from setup_wizard.forms import StartupWizardTlsCertificateForm

from management.forms import IPv4AddressForm, TlsAddFileImportPkcs12Form
from management.models import TlsSettings
from trustpoint.views.base import ContextDataMixin

if TYPE_CHECKING:
    from typing import Any, ClassVar

    from django.http import HttpResponse


class TlsSettingsContextMixin:
    """Mixin which adds data to the context for the TLS settings application."""

    extra_context: ClassVar = {'page_category': 'management', 'page_name': 'tls'}

class TlsView(TlsSettingsContextMixin, FormView[IPv4AddressForm]):
    """View to display certificate details, including Subject Alternative Name (SAN) and associated IP addresses."""
    template_name = 'management/tls.html'
    form_class = IPv4AddressForm
    success_url = reverse_lazy('management:tls')

    def get_form_kwargs(self) -> dict[str, Any]:
        """Pass additional arguments (e.g., SAN IPs) to the form."""
        kwargs = super().get_form_kwargs()

        try:
            network_settings = TlsSettings.objects.get(id=1)
            saved_ipv4_address = network_settings.ipv4_address
        except TlsSettings.DoesNotExist:
            saved_ipv4_address = None

        san_ips = self.get_san_ips()

        kwargs['data'] = self.request.POST or None
        kwargs['initial'] = {'ipv4_address': saved_ipv4_address or (san_ips[0] if san_ips else '')}
        kwargs['san_ips'] = san_ips
        return kwargs

    def get_context_data(self, **kwargs: dict[str, Any]) -> dict[str, Any]:
        """Add certificate information, including SAN data and issuer details, to the context for display."""
        context = super().get_context_data(**kwargs)

        try:
            active_credential = ActiveTrustpointTlsServerCredentialModel.objects.select_related('credential').get(id=1)
        except ActiveTrustpointTlsServerCredentialModel.DoesNotExist:
            active_credential = None

        certificate = None
        if active_credential and active_credential.credential:
            certificate = active_credential.credential.certificate

        san_ips = []
        san_dns_names = []
        issuer_details: dict[str, Optional[str]] = {
            'country': None,
            'organization': None,
            'common_name': None,
        }

        if certificate and certificate.subject_alternative_name_extension:
            san_model = certificate.subject_alternative_name_extension.subject_alt_name

            if san_model:
                san_ips = [str(ip_entry.value) for ip_entry in san_model.ip_addresses.all()]
                san_dns_names = [dns_entry.value for dns_entry in san_model.dns_names.all()]

        if certificate and certificate.issuer.exists():
            issuer_mapping = {
                '2.5.4.6': 'country',
                '2.5.4.10': 'organization',
                '2.5.4.3': 'common_name',
            }

            for attribute in certificate.issuer.all():
                if attribute.oid in issuer_mapping:
                    field = issuer_mapping[attribute.oid]
                    issuer_details[field] = attribute.value

        tls_certificates = CertificateModel.objects.filter(
            credential__credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER)

        context.update({
            'certificate': certificate,
            'san_ips': san_ips,
            'san_dns_names': san_dns_names,
            'issuer_details': issuer_details,
            'tls_certificates': tls_certificates,
            'tls_form': StartupWizardTlsCertificateForm()
        })

        return context

    def form_valid(self, form: IPv4AddressForm) -> HttpResponse:
        """Handle valid form submissions."""
        ipv4_address = form.cleaned_data.get('ipv4_address')
        TlsSettings.objects.update_or_create(
            id=1,
            defaults={'ipv4_address': ipv4_address},
        )
        messages.success(self.request, 'IPv4 address saved successfully.')
        return super().form_valid(form)

    def form_invalid(self, form: IPv4AddressForm) -> HttpResponse:
        """Handle invalid form submissions."""
        messages.error(self.request, 'Invalid IPv4 address selected.')
        return super().form_invalid(form)

    def get_san_ips(self) -> list[str]:
        """Fetches IPv4 addresses from the Subject Alternative Name (SAN) extension of the active TLS certificate.

        Returns:
            A list of IPv4 addresses (as strings) or an empty list if none are found.
        """
        try:
            try:
                active_credential = ActiveTrustpointTlsServerCredentialModel.objects.select_related('credential').get(
                    id=1)
            except ActiveTrustpointTlsServerCredentialModel.DoesNotExist:
                active_credential = None

            certificate = None
            if active_credential and active_credential.credential:
                certificate = active_credential.credential.certificate

            if not certificate or not certificate.subject_alternative_name_extension:
                return []

            san_model = certificate.subject_alternative_name_extension.subject_alt_name
            if not san_model:
                return []

            ipv4_addresses = GeneralNameIpAddress.objects.filter(
                general_names_set=san_model, ip_type=GeneralNameIpAddress.IpType.IPV4_ADDRESS
            ).values_list('value', flat=True)

            return list(ipv4_addresses)

        except ObjectDoesNotExist:
            return []


class TlsAddMethodSelectView(TemplateView):
    """View to select the method to add a TLS Certificate."""

    template_name = 'management/tls/method_select.html'
    success_url = reverse_lazy('management:tls-add-method-select')



class GenerateTlsCertificateView(TemplateView):
    """View to generate self-signed TLS server certificate."""

    template_name = 'management/tls/generate_tls.html'
    success_url = reverse_lazy('management:tls')

    def get_context_data(self, **kwargs):
        """Add TLS Certificate Form."""

        context = super().get_context_data(**kwargs)
        context['tls_form'] = StartupWizardTlsCertificateForm()
        return context


class TlsAddFileImportPkcs12View(TlsSettingsContextMixin, FormView[TlsAddFileImportPkcs12Form]):
    """View to import an TLS-Server Credential from a PKCS12 file."""

    template_name = 'management/tls/file_import.html'
    form_class = TlsAddFileImportPkcs12Form
    success_url = reverse_lazy('management:tls')

    def form_valid(self, form: TlsAddFileImportPkcs12Form) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added TLS-Server Credential.'),
        )
        return super().form_valid(form)


class ActivateTlsServerView(View):
    """Activate a TLS server certificate."""

    def post(self, request, *args, **kwargs):
        cert_id = kwargs['pk']
        tls_certificate = CredentialModel.objects.get(
            certificate__id=cert_id)

        active_tls, _ = ActiveTrustpointTlsServerCredentialModel.objects.get_or_create(id=1)
        active_tls.credential = tls_certificate
        active_tls.save()
        messages.success(request, f"TLS Server certificate activated successfully")
        return redirect(reverse('management:tls'))









