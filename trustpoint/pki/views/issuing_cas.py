"""Views for Issuing CA management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.db.models import ProtectedError
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView

from pki.forms import (
    IssuingCaAddFileImportPkcs12Form,
    IssuingCaAddFileImportSeparateFilesForm,
    IssuingCaAddMethodSelectForm,
)
from pki.models import IssuingCaModel
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    LoggerMixin,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from django.forms import Form
    from django.http import HttpRequest


class IssuingCaContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'issuing_cas'


class IssuingCaTableView(IssuingCaContextMixin, SortableTableMixin, ListView[IssuingCaModel]):
    """Issuing CA Table View."""

    model = IssuingCaModel
    template_name = 'pki/issuing_cas/issuing_cas.html'  # Template file
    context_object_name = 'issuing_ca'
    paginate_by = UIConfig.paginate_by  # Number of items per page
    default_sort_param = 'unique_name'


class IssuingCaAddMethodSelectView(IssuingCaContextMixin, FormView[IssuingCaAddMethodSelectForm]):
    """View to select the method to add an Issuing CA."""

    template_name = 'pki/issuing_cas/add/method_select.html'
    form_class = IssuingCaAddMethodSelectForm

    def form_valid(self, form: IssuingCaAddMethodSelectForm) -> HttpResponseRedirect:
        """Redirect to the next step based on the selected method."""
        method_select = form.cleaned_data.get('method_select')
        if not method_select:
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))

        if method_select and method_select == 'local_file_import':
            return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-file_import-file_type_select'))

        return HttpResponseRedirect(reverse_lazy('pki:issuing_cas-add-method_select'))


class IssuingCaAddFileImportPkcs12View(
    IssuingCaContextMixin, FormView[IssuingCaAddFileImportPkcs12Form]
):
    """View to import an Issuing CA from a PKCS12 file."""

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportPkcs12Form
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaAddFileImportSeparateFilesView(
    IssuingCaContextMixin, FormView[IssuingCaAddFileImportSeparateFilesForm]
):
    """View to import an Issuing CA from separate PEM files."""

    template_name = 'pki/issuing_cas/add/file_import.html'
    form_class = IssuingCaAddFileImportSeparateFilesForm
    success_url = reverse_lazy('pki:issuing_cas')


class IssuingCaDetailView(IssuingCaContextMixin, DetailView[IssuingCaModel]):
    """View to display the details of an Issuing CA."""

    http_method_names = ('get',)

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/details.html'
    context_object_name = 'issuing_ca'


class IssuingCaConfigView(LoggerMixin, IssuingCaContextMixin, DetailView[IssuingCaModel]):
    """View to configure an Issuing CA."""

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/config.html'
    context_object_name = 'issuing_ca'


class IssuingCaBulkDeleteConfirmView(IssuingCaContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple Issuing CAs."""

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    template_name = 'pki/issuing_cas/confirm_delete.html'
    context_object_name = 'issuing_cas'

    def form_valid(self, form: Form) -> HttpResponse:
        """Delete the selected Issuing CAs on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count()

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected Issuing CA(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} Issuing CA(s).').format(count=deleted_count))

        return response


class IssuingCaCrlGenerationView(IssuingCaContextMixin, DetailView[IssuingCaModel]):
    """View to manually generate a CRL for an Issuing CA."""

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    context_object_name = 'issuing_ca'

    http_method_names = ('get',)

    # TODO(Air): This view should use a POST request as it is an action.
    # However, this is not trivial in the config view as that already contains a form.
    def get(self, request: HttpRequest, *_args: tuple[Any], **_kwargs: dict[str, Any]) -> HttpResponse:
        """Generate a CRL for the Issuing CA (should be POST!)."""
        issuing_ca = self.get_object()
        if issuing_ca.issue_crl():
            messages.success(request, _('CRL for Issuing CA %s has been generated.') % issuing_ca.unique_name)
        else:
            messages.error(request, _('Failed to generate CRL for Issuing CA %s.') % issuing_ca.unique_name)
        return redirect('pki:issuing_cas-config', pk=issuing_ca.id)


class CrlDownloadView(IssuingCaContextMixin, DetailView[IssuingCaModel]):
    """Unauthenticated view to download the certificate revocation list of an Issuing CA."""

    http_method_names = ('get',)

    model = IssuingCaModel
    success_url = reverse_lazy('pki:issuing_cas')
    ignore_url = reverse_lazy('pki:issuing_cas')
    context_object_name = 'issuing_ca'

    def get(self, request: HttpRequest, *_args: tuple[Any], **_kwargs: dict[str, Any]) -> HttpResponse:
        """Download the CRL of the Issuing CA."""
        issuing_ca = self.get_object()
        crl_pem = issuing_ca.crl_pem
        if not crl_pem:
            messages.warning(request, _('No CRL available for issuing CA %s.') % issuing_ca.unique_name)
            return redirect('pki:issuing_cas')
        response = HttpResponse(crl_pem, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{issuing_ca.unique_name}.crl"'
        return response
