"""Views for Owner Credential (DevOwnerID) management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormView
from django.views.generic.list import ListView
from trustpoint.logger import LoggerMixin
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    SortableTableMixin,
)

from pki.forms import OwnerCredentialFileImportForm
from pki.models import OwnerCredentialModel
from trustpoint.settings import UIConfig

if TYPE_CHECKING:
    from django.forms import Form


class OwnerCredentialContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Issuing CAs pages."""

    context_page_category = 'pki'
    context_page_name = 'owner_credentials'


class OwnerCredentialTableView(
    OwnerCredentialContextMixin, SortableTableMixin[OwnerCredentialModel], ListView[OwnerCredentialModel]):
    """Owner Credential Table View."""

    model = OwnerCredentialModel
    template_name = 'pki/owner_credentials/owner_credentials.html'  # Template file
    context_object_name = 'owner_credential'
    paginate_by = UIConfig.paginate_by  # Number of items per page
    default_sort_param = 'unique_name'


class OwnerCredentialDetailView(LoggerMixin, OwnerCredentialContextMixin, DetailView[OwnerCredentialModel]):
    """View to display the details of an Issuing CA."""

    http_method_names = ('get',)

    model = OwnerCredentialModel
    success_url = reverse_lazy('pki:owner_credentials')
    ignore_url = reverse_lazy('pki:owner_credentials')
    template_name = 'pki/owner_credentials/details.html'
    context_object_name = 'owner_credential'

    # add idevid refs to the context
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the issued certificates to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        owner_credential = self.get_object()
        idevid_refs: list[dict[str,str]] = []
        if owner_credential:
            idevid_refs.extend(
                {
                    'idevid_subj_sn': ref.idevid_subject_serial_number,
                    'idevid_x509_sn': ref.idevid_x509_serial_number,
                    'idevid_sha256_fingerprint': ref.idevid_sha256_fingerprint,
                } for ref in owner_credential.idevid_ref_set.all()
            )

        context['idevid_refs'] = idevid_refs
        return context


class OwnerCredentialAddView(OwnerCredentialContextMixin, FormView[OwnerCredentialFileImportForm]):
    """View to import a DevOwnerID from separate PEM files."""

    template_name = 'pki/owner_credentials/add.html'
    form_class = OwnerCredentialFileImportForm
    success_url = reverse_lazy('pki:owner_credentials')

    def form_valid(self, form: OwnerCredentialFileImportForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added DevOwnerID {name}.').format(name=form.cleaned_data['unique_name']),
        )
        return super().form_valid(form)


class OwnerCredentialBulkDeleteConfirmView(OwnerCredentialContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple owner credentials."""

    model = OwnerCredentialModel
    success_url = reverse_lazy('pki:owner_credentials')
    ignore_url = reverse_lazy('pki:owner_credentials')
    template_name = 'pki/owner_credentials/confirm_delete.html'
    context_object_name = 'owner_credentials'

    def form_valid(self, form: Form) -> HttpResponse:
        """Delete the selected credentials on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected DevOwnerID(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} DevOwnerID(s).').format(count=deleted_count))

        return response
