"""Views for Certificate Profile management."""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.db.models import ProtectedError, QuerySet
from django.forms import ValidationError
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.edit import FormView, UpdateView
from django.views.generic.list import ListView

from pki.forms import CertProfileConfigForm, CertificateIssuanceForm
from pki.models import CertificateProfileModel
from trustpoint.logger import LoggerMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    SortableTableMixin,
)

if TYPE_CHECKING:
    from django.forms import Form


class CertProfileContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the PKI -> Cert Profiles pages."""

    context_page_category = 'pki'
    context_page_name = 'cert_profiles'


class CertProfileTableView(CertProfileContextMixin,
                           SortableTableMixin[CertificateProfileModel],
                           ListView[CertificateProfileModel]):
    """Certificate Profile Table View."""

    model = CertificateProfileModel
    template_name = 'pki/cert_profiles/cert_profiles.html'  # Template file
    context_object_name = 'cert_profiles'
    paginate_by = UIConfig.paginate_by  # Number of items per page
    default_sort_param = 'unique_name'


class CertProfileConfigView(LoggerMixin, CertProfileContextMixin,
                            UpdateView[CertificateProfileModel, CertProfileConfigForm]):
    """View to display the details of and edit a Certificate Profile."""

    http_method_names = ('get', 'post')

    model = CertificateProfileModel
    success_url = reverse_lazy('pki:cert_profiles')
    template_name = 'pki/cert_profiles/config.html'
    context_object_name = 'profile'
    form_class = CertProfileConfigForm

    # this is an LSP violation as superclass cannot return None, but makes sense to not add a duplicate "add" view
    def get_object(self, _queryset: QuerySet[Any, Any] | None = None) -> CertificateProfileModel | None:  # type: ignore[override]
        """Retrieve the CertificateProfileModel object based on the primary key in the URL."""
        pk = self.kwargs.get('pk')
        if pk:
            return get_object_or_404(CertificateProfileModel, pk=pk)
        return None  # Add view case

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        form = context['form']

        raw_json = form['profile_json'].value()

        if not form['unique_name'].value():
            context['is_new'] = True

        default_json = { # new profile default
            'type': 'cert_profile',
            'subj': {},
            'ext': {},
        }

        context['json_valid'] = True

        if not raw_json or raw_json == 'null':
            context['profile_json'] = default_json
            return context

        cleaned_raw = raw_json.encode('utf-8').decode('unicode_escape')
        if cleaned_raw.startswith('"') and cleaned_raw.endswith('"'):
            cleaned_raw = cleaned_raw[1:-1]

        with contextlib.suppress(json.JSONDecodeError):
            context['profile_json'] = json.loads(cleaned_raw)
            return context

        with contextlib.suppress(json.JSONDecodeError):
            context['profile_json'] = json.loads(raw_json)
            return context

        # Invalid JSON typed by the user - render as-is to revise
        context['json_valid'] = False
        context['profile_json'] = cleaned_raw
        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        initial['unique_name'] = self.object.unique_name if self.object else ''
        return initial

    def form_valid(self, form: CertProfileConfigForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        cert_profile = form.save()
        messages.success(
            self.request,
            _('Successfully updated Certificate Profile {name}.').format(name=cert_profile.unique_name),
        )
        return super().form_valid(form)


class CertProfileIssuanceView(LoggerMixin, CertProfileContextMixin,
                              FormView[CertificateIssuanceForm]):
    """View to display the issuance form for a Certificate Profile."""

    http_method_names = ('get', 'post')
    template_name = 'pki/cert_profiles/issuance.html'
    form_class = CertificateIssuanceForm

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Dispatch the request, ensuring the profile exists."""
        self.profile = get_object_or_404(CertificateProfileModel, pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self) -> dict[str, Any]:
        """Get form kwargs, including the profile."""
        kwargs = super().get_form_kwargs()
        raw_profile = json.loads(self.profile.profile_json)
        kwargs['profile'] = raw_profile
        return kwargs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data."""
        context = super().get_context_data(**kwargs)
        context['profile'] = self.profile
        context['profile_dict'] = self.get_form_kwargs()['profile']
        return context

    def form_valid(self, form: CertificateIssuanceForm) -> HttpResponse:
        """Handle the case where the form is valid."""
        # For now, just redirect back
        messages.success(
            self.request,
            _('Certificate issuance data submitted successfully.'),
        )
        return HttpResponseRedirect(reverse_lazy('pki:cert_profiles'))


class CertProfileBulkDeleteConfirmView(CertProfileContextMixin, BulkDeleteView):
    """View to confirm the deletion of multiple certificate profiles."""

    model = CertificateProfileModel
    success_url = reverse_lazy('pki:cert_profiles')
    ignore_url = reverse_lazy('pki:cert_profiles')
    template_name = 'pki/cert_profiles/confirm_delete.html'
    context_object_name = 'cert_profiles'
    queryset: QuerySet[CertificateProfileModel]

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No certificate profiles selected for deletion.'))
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

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
