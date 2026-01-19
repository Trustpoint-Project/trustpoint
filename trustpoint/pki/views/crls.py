"""CRL views for the PKI application."""

import binascii
import logging
from typing import Any

from cryptography import x509
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError, QuerySet
from django.forms import Form
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic import ListView
from django.views.generic.detail import DetailView

from pki.models import CrlModel
from trustpoint.views.base import BulkDeleteView, ContextDataMixin

logger = logging.getLogger(__name__)


class CrlTableView(ContextDataMixin, ListView[CrlModel]):
    """Table view for all CRLs."""

    model = CrlModel
    template_name = 'pki/crls/crls.html'
    context_object_name = 'crls'
    paginate_by = None

    # Context attributes for sidebar navigation
    context_page_category = 'pki'
    context_page_name = 'crls'

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


class CrlDownloadView(ContextDataMixin, DetailView[CrlModel]):
    """View for downloading a single CRL."""

    model = CrlModel
    success_url = reverse_lazy('pki:crls')
    ignore_url = reverse_lazy('pki:crls')
    template_name = 'pki/crls/download.html'
    context_object_name = 'crl'

    # Context attributes for sidebar navigation
    context_page_category = 'pki'
    context_page_name = 'crls'

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
            # Convert PEM to DER
            pem_lines = [line.strip() for line in crl_model.crl_pem.splitlines() if line and not line.startswith('-----')]
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
            # For PKCS#7, we currently return the CRL as-is
            # TODO: Implement proper PKCS#7 packaging for CRLs
            if file_format == 'pkcs7_pem':
                file_bytes = crl_model.crl_pem.encode()
                mime_type = 'application/x-pem-file'
                file_extension = '.p7c'
            else:
                # Convert PEM to DER for PKCS#7 DER
                pem_lines = [line.strip() for line in crl_model.crl_pem.splitlines() if line and not line.startswith('-----')]
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

        # Generate filename
        ca_name_safe = ''.join(c if c.isalnum() or c in '._-' else '_' for c in crl_model.ca.unique_name)
        if crl_model.crl_number:
            file_name = f'{ca_name_safe}_crl_{crl_model.crl_number}{file_extension}'
        else:
            file_name = f'{ca_name_safe}_crl{file_extension}'

        response = HttpResponse(file_bytes, content_type=mime_type)
        response['Content-Disposition'] = f'attachment; filename="{file_name}"'

        return response
