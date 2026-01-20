"""CRL views for the PKI application."""

import binascii
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError, QuerySet
from django.forms import Form
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic import ListView
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView

from pki.models import CaModel, CertificateModel, CrlModel
from trustpoint.views.base import BulkDeleteView, ContextDataMixin


class CrlContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> CRLs pages."""

    context_page_category = 'pki'
    context_page_name = 'crls'


class CrlTableView(CrlContextMixin, ListView[CrlModel]):
    """Table view for all CRLs."""

    model = CrlModel
    template_name = 'pki/crls/crls.html'
    context_object_name = 'crls'
    paginate_by = None

    def get_queryset(self) -> QuerySet[CrlModel]:
        """Return all CRL models with related CA information."""
        return (super().get_queryset()
               .select_related('ca')
               .order_by('-this_update'))


class CrlBulkDeleteConfirmView(BulkDeleteView):
    """View to confirm the deletion of multiple CRLs."""

    model = CrlModel
    success_url = reverse_lazy('pki:crls')
    ignore_url = reverse_lazy('pki:crls')
    template_name = 'pki/crls/confirm_delete.html'
    context_object_name = 'crls'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No CRLs selected for deletion.'))
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Form) -> HttpResponse:
        """Delete the selected CRLs on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected CRL(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} CRL(s).').format(count=deleted_count))

        return response


class CrlDownloadView(CrlContextMixin, DetailView[CrlModel]):
    """View for downloading a single CRL."""

    model = CrlModel
    success_url = reverse_lazy('pki:crls')
    ignore_url = reverse_lazy('pki:crls')
    template_name = 'pki/crls/download.html'
    context_object_name = 'crl'

    def get_queryset(self) -> QuerySet[CrlModel]:
        """Return all CRL models with related CA information."""
        return super().get_queryset().select_related('ca')

    def get(
        self,
        request: HttpRequest,
        pk: str | None = None,
        file_format: str | None = None,
        *args: tuple[Any],
        **kwargs: dict[str, Any],
    ) -> HttpResponse:
        """HTTP GET Method.

        If only the CRL primary key are passed in the url, the download summary will be displayed.
        If value for file_format is also provided, a file download will be performed.

        Args:
            request: The HttpRequest object.
            pk: A string containing the CRL primary key.
            file_format: The format of the CRL to download.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            HttpResponse: The HTTP response with either the download summary or a file download.

        Raises:
            Http404
        """
        if not pk:
            raise Http404

        if file_format is None:
            return super().get(request, *args, **kwargs)

        crl_model = self.get_object()

        if file_format == 'pem':
            file_bytes = crl_model.crl_pem.encode()
            mime_type = 'application/x-pem-file'
            file_extension = '.crl'
        elif file_format == 'der':
            pem_lines = [
                line.strip()
                for line in crl_model.crl_pem.splitlines()
                if line and not line.startswith('-----')
            ]
            b64data = ''.join(pem_lines)
            try:
                file_bytes = binascii.a2b_base64(b64data)
                mime_type = 'application/pkix-crl'
                file_extension = '.crl.der'
            except (binascii.Error, ValueError) as exc:
                messages.error(
                    request,
                    _('Failed to convert CRL to DER: %s') % str(exc),
                )
                return HttpResponseRedirect(self.success_url)
        elif file_format in ['pkcs7_pem', 'pkcs7_der']:
            if file_format == 'pkcs7_pem':
                file_bytes = crl_model.crl_pem.encode()
                mime_type = 'application/x-pem-file'
                file_extension = '.p7c'
            else:
                pem_lines = [
                    line.strip()
                    for line in crl_model.crl_pem.splitlines()
                    if line and not line.startswith('-----')
                ]
                b64data = ''.join(pem_lines)
                try:
                    file_bytes = binascii.a2b_base64(b64data)
                    mime_type = 'application/pkcs7-mime'
                    file_extension = '.p7c.der'
                except (binascii.Error, ValueError) as exc:
                    messages.error(
                        request,
                        _('Failed to convert CRL to PKCS#7 DER: %s') % str(exc),
                    )
                    return HttpResponseRedirect(self.success_url)
        else:
            raise Http404

        ca_name = crl_model.ca.unique_name if crl_model.ca else 'no_ca'
        ca_name_safe = ''.join(c if c.isalnum() or c in '._-' else '_' for c in ca_name)
        if crl_model.crl_number:
            file_name = f'{ca_name_safe}_crl_{crl_model.crl_number}{file_extension}'
        else:
            file_name = f'{ca_name_safe}_crl{file_extension}'

        response = HttpResponse(file_bytes, content_type=mime_type)
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'

        return response

class CrlDetailView(CrlContextMixin, DetailView[CrlModel]):
    """Detail view for a single CRL."""

    model = CrlModel
    success_url = reverse_lazy('pki:crls')
    ignore_url = reverse_lazy('pki:crls')
    template_name = 'pki/crls/details.html'
    context_object_name = 'crl'

    def get_queryset(self) -> QuerySet[CrlModel]:
        """Return CRL models with related CA information."""
        return super().get_queryset().select_related('ca')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data for the CRL detail view."""
        context = super().get_context_data(**kwargs)
        crl = context['crl']

        crypto_crl = crl.get_crl_as_crypto()

        # Extract issuer information for display
        issuer_rdns = crypto_crl.issuer
        issuer_parts = []
        for rdn in issuer_rdns:
            oid_name = getattr(rdn.oid, '_name', str(rdn.oid))
            issuer_parts.append(f'{oid_name}={rdn.value}')
        context['crl_issuer'] = ', '.join(issuer_parts)

        revoked_certs = []
        serial_numbers = [f'{revoked_cert.serial_number:x}'.upper() for revoked_cert in crypto_crl]

        certificates_by_serial = {}
        if serial_numbers:
            certificates = CertificateModel.objects.filter(serial_number__in=serial_numbers)
            certificates_by_serial = {cert.serial_number: cert.id for cert in certificates}

        for revoked_cert in crypto_crl:
            serial_hex = f'{revoked_cert.serial_number:x}'.upper()
            cert_id = certificates_by_serial.get(serial_hex)
            revoked_certs.append({
                'serial_number': revoked_cert.serial_number,
                'serial_number_hex': serial_hex,
                'revocation_date': revoked_cert.revocation_date_utc,
                'reason': getattr(revoked_cert, 'reason', None),
                'certificate_id': cert_id,
            })
        context['revoked_certificates'] = revoked_certs

        extensions = [
            {
                'oid': ext.oid.dotted_string,
                'name': getattr(ext.oid, '_name', str(ext.oid)),
                'critical': ext.critical,
                'value': ext.value,
            }
            for ext in crypto_crl.extensions
        ]
        context['extensions'] = extensions

        return context


class CrlImportForm(forms.Form):
    """Form for importing CRLs."""

    crl_file = forms.FileField(
        label=_('CRL File'),
        help_text=_('Select the CRL file to import (PEM, DER, PKCS#7 PEM, or PKCS#7 DER format)'),
        required=True,
    )

    ca: forms.ModelChoiceField[CaModel] = forms.ModelChoiceField(
        label=_('Certificate Authority'),
        queryset=None,  # Will be set in __init__
        help_text=_('Select the CA that issued this CRL (optional)'),
        required=False,
    )

    set_active = forms.BooleanField(
        label=_('Set as Active CRL'),
        initial=True,
        required=False,
        help_text=_('Make this the active CRL for the selected CA (only applies when a CA is selected)'),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        super().__init__(*args, **kwargs)
        ca_field = self.fields['ca']
        if isinstance(ca_field, forms.ModelChoiceField):
            ca_field.queryset = CaModel.objects.all().order_by('unique_name')
            ca_field.label_from_instance = lambda obj: obj.common_name  # type: ignore


class CrlImportView(CrlContextMixin, FormView[CrlImportForm]):
    """View for importing CRLs."""

    form_class = CrlImportForm
    template_name = 'pki/crls/import.html'
    success_url = reverse_lazy('pki:crls')

    def form_valid(self, form: CrlImportForm) -> HttpResponse:
        """Handle valid form submission."""
        crl_file = form.cleaned_data['crl_file']
        ca: CaModel | None = form.cleaned_data['ca']
        set_active = form.cleaned_data['set_active']

        try:
            file_content = crl_file.read()

            crl_pem = self._convert_to_pem(file_content)

            CrlModel.create_from_pem(
                ca=ca,
                crl_pem=crl_pem,
                set_active=set_active and ca is not None,
            )

            if ca is not None:
                messages.success(
                    self.request,
                    _('Successfully imported CRL for CA %(ca)s.') % {'ca': ca.unique_name}
                )
            else:
                messages.success(
                    self.request,
                    _('Successfully imported CRL with no associated CA.')
                )

        except ValidationError as exc:
            messages.error(self.request, str(exc))
            return self.form_invalid(form)
        except (ValueError, UnicodeDecodeError) as exc:
            messages.error(
                self.request,
                _('Failed to import CRL: %(error)s') % {'error': str(exc)}
            )
            return self.form_invalid(form)

        return super().form_valid(form)

    def _convert_to_pem(self, file_content: bytes) -> str:
        """Convert file content to PEM format by automatically detecting the format.

        Args:
            file_content: The raw file content as bytes

        Returns:
            str: The CRL in PEM format

        Raises:
            ValidationError: If the conversion fails for all supported formats
        """
        # List of conversion functions to try in order
        converters = [
            self._try_pem,
            self._try_der,
            self._try_pkcs7_pem,
            self._try_pkcs7_der,
        ]

        for converter in converters:
            try:
                return converter(file_content)
            except (ValueError, UnicodeDecodeError):
                continue

        raise ValidationError(_('Unable to parse CRL. The file may be corrupted or in an unsupported format.'))

    def _try_pem(self, file_content: bytes) -> str:
        """Try to load as PEM format."""
        pem_str = file_content.decode('utf-8')
        x509.load_pem_x509_crl(pem_str.encode())
        return pem_str

    def _try_der(self, file_content: bytes) -> str:
        """Try to load as DER format."""
        crl = x509.load_der_x509_crl(file_content)
        return crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def _try_pkcs7_pem(self, file_content: bytes) -> str:
        """Try to load as PKCS#7 PEM format."""
        pem_str = file_content.decode('utf-8')
        # TODO (FHK): For now, assume the PKCS#7 contains a CRL and try to load it directly  # noqa: FIX002
        x509.load_pem_x509_crl(pem_str.encode())
        return pem_str

    def _try_pkcs7_der(self, file_content: bytes) -> str:
        """Try to load as PKCS#7 DER format."""
        # TODO (FHK): For now, assume the PKCS#7 contains a CRL and try to load it directly  # noqa: FIX002
        crl = x509.load_der_x509_crl(file_content)
        return crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')
