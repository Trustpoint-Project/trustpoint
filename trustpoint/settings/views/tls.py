from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse_lazy
from django.views.generic import FormView
from django.contrib import messages
from django.utils.translation import gettext as _
from django import forms

from pki.models import GeneralNameIpAddress
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from settings.forms import IPv4AddressForm
from settings.models import TlsSettings


class TlsView(FormView):
    """
    View to display certificate details, including Subject Alternative Name (SAN) and associated IP addresses.
    """
    template_name = "settings/tls.html"
    form_class = IPv4AddressForm
    success_url = reverse_lazy('settings:tls')

    def get_form_kwargs(self):
        """
        Pass additional arguments (e.g., SAN IPs) to the form.
        """
        kwargs = super().get_form_kwargs()

        try:
            network_settings = TlsSettings.objects.get(id=1)
            saved_ipv4_address = network_settings.ipv4_address
        except TlsSettings.DoesNotExist:
            saved_ipv4_address = None

        san_ips = self.get_san_ips()

        kwargs["data"] = self.request.POST or None
        kwargs["initial"] = {"ipv4_address": saved_ipv4_address or (san_ips[0] if san_ips else "")}
        kwargs["san_ips"] = san_ips
        return kwargs

    def get_context_data(self, **kwargs):
        """
        Add certificate information, including SAN data and issuer details, to the context for display.
        """
        context = super().get_context_data(**kwargs)

        try:
            active_credential = ActiveTrustpointTlsServerCredentialModel.objects.select_related("credential").get(id=1)
            certificate = active_credential.credential.certificate

            san_ips = []
            san_dns_names = []
            issuer_details = {
                "country": None,
                "organization": None,
                "common_name": None,
            }

            if certificate and certificate.subject_alternative_name_extension:
                san_model = certificate.subject_alternative_name_extension.subject_alt_name

                if san_model:
                    san_ips = [str(ip_entry.value) for ip_entry in san_model.ip_addresses.all()]
                    san_dns_names = [dns_entry.value for dns_entry in san_model.dns_names.all()]

            if certificate.issuer.exists():
                issuer_mapping = {
                    "2.5.4.6": "country",
                    "2.5.4.10": "organization",
                    "2.5.4.3": "common_name",
                }

                for attribute in certificate.issuer.all():
                    if attribute.oid in issuer_mapping:
                        field = issuer_mapping[attribute.oid]
                        issuer_details[field] = attribute.value

            context.update({
                "certificate": certificate,
                "san_ips": san_ips,
                "san_dns_names": san_dns_names,
                "issuer_details": issuer_details,  # Pass issuer information to the template
            })

        except ActiveTrustpointTlsServerCredentialModel.DoesNotExist:
            messages.warning(self.request, _("No active TLS credential configured."))
            context.update({
                "certificate": None,
                "san_ips": [],
                "san_dns_names": [],
                "issuer_details": None,
            })

        return context

    def form_valid(self, form):
        """Handle valid form submissions."""
        ipv4_address = form.cleaned_data.get("ipv4_address")
        TlsSettings.objects.update_or_create(
            id=1,
            defaults={"ipv4_address": ipv4_address},
        )
        messages.success(self.request, "IPv4 address saved successfully.")
        return super().form_valid(form)

    def form_invalid(self, form):
        """Handle invalid form submissions."""
        messages.error(self.request, "Invalid IPv4 address selected.")
        return super().form_invalid(form)

    def get_san_ips(self):
        """
        Fetches IPv4 addresses from the Subject Alternative Name (SAN) extension
        of the active TLS certificate.

        Returns:
            A list of IPv4 addresses (as strings) or an empty list if none are found.
        """
        try:
            active_credential = ActiveTrustpointTlsServerCredentialModel.objects.select_related("credential").get(id=1)
            certificate = active_credential.credential.certificate

            if not certificate or not certificate.subject_alternative_name_extension:
                return []

            san_model = certificate.subject_alternative_name_extension.subject_alt_name
            if not san_model:
                return []

            ipv4_addresses = GeneralNameIpAddress.objects.filter(
                general_names_set=san_model, ip_type=GeneralNameIpAddress.IpType.IPV4_ADDRESS
            ).values_list("value", flat=True)

            return list(ipv4_addresses)

        except ObjectDoesNotExist:
            return []









