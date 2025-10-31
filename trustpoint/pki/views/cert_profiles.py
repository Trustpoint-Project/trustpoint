"""Views for Certificate Profile management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError, QuerySet
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
from pki.models import CertificateProfileModel
from trustpoint.settings import UIConfig

if TYPE_CHECKING:
    from django.forms import Form


class CertProfileContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Cert Profiles pages."""

    context_page_category = 'pki'
    context_page_name = 'cert_profiles'


class CertProfileTableView(CertProfileContextMixin, SortableTableMixin, ListView[CertificateProfileModel]):
    """Certificate Profile Table View."""

    model = CertificateProfileModel
    template_name = 'pki/cert_profiles/cert_profiles.html'  # Template file
    context_object_name = 'cert_profiles'
    paginate_by = UIConfig.paginate_by  # Number of items per page
    default_sort_param = 'unique_name'


class CertProfileConfigView(LoggerMixin, CertProfileContextMixin, DetailView[CertificateProfileModel]):
    """View to display the details of and edit a Certificate Profile."""

    http_method_names = ('get',)

    model = CertificateProfileModel
    success_url = reverse_lazy('pki:cert_profiles')
    ignore_url = reverse_lazy('pki:cert_profiles')
    template_name = 'pki/cert_profiles/config.html'
    context_object_name = 'cert_profile'

    # add idevid refs to the context
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the issued certificates to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        cert_profile = self.get_object()
        context['profile'] = cert_profile

        return context


class CertProfileAddView(CertProfileContextMixin, FormView[OwnerCredentialFileImportForm]):
    """View to import a Certificate Profile from a .json file."""

    template_name = 'pki/cert_profiles/add.html'
    form_class = OwnerCredentialFileImportForm
    success_url = reverse_lazy('pki:cert_profiles')

    def form_valid(self, form: OwnerCredentialFileImportForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        messages.success(
            self.request,
            _('Successfully added Certificate Profile {name}.').format(name=form.cleaned_data['unique_name']),
        )
        return super().form_valid(form)


class CertProfileBulkDeleteConfirmView(CertProfileContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple certificate profiles."""

    model = CertificateProfileModel
    success_url = reverse_lazy('pki:cert_profiles')
    ignore_url = reverse_lazy('pki:cert_profiles')
    template_name = 'pki/cert_profiles/confirm_delete.html'
    context_object_name = 'cert_profiles'
    queryset: QuerySet[CertificateProfileModel]

    def form_valid(self, form: Form) -> HttpResponse:
        """Delete the selected credentials on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected Certificate Profile(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} certificate profile(s).')
                .format(count=deleted_count))

        return response
