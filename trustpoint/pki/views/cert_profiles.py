"""Views for Certificate Profile management."""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING, Any, ClassVar

from django.contrib import messages
from django.db.models import ProtectedError, QuerySet
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.base import TemplateView
from django.views.generic.edit import UpdateView
from django.views.generic.list import ListView
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from pydantic import ValidationError
from rest_framework import filters, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from trustpoint.logger import LoggerMixin
from trustpoint.views.base import (
    BulkDeleteView,
    ContextDataMixin,
    SortableTableMixin,
)

from pki.forms import CertProfileConfigForm
from pki.models import CertificateProfileModel
from pki.serializer.cert_profile import CertProfileSerializer
from pki.util.cert_profile import CertProfileModel as CertProfilePydanticModel
from trustpoint.settings import UIConfig

if TYPE_CHECKING:
    from django.forms import Form

    from pki.forms import OwnerCredentialFileImportForm


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


class CertProfileConfigView(LoggerMixin, CertProfileContextMixin, UpdateView[CertificateProfileModel, CertProfileConfigForm]):
    """View to display the details of and edit a Certificate Profile."""

    http_method_names = ('get', 'post')

    model = CertificateProfileModel
    success_url = reverse_lazy('pki:cert_profiles')
    #ignore_url = reverse_lazy('pki:cert_profiles')
    template_name = 'pki/cert_profiles/config.html'
    context_object_name = 'profile'
    form_class = CertProfileConfigForm

    def get_object(self, queryset: QuerySet[Any, Any] | None = None) -> CertificateProfileModel | None:
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



class CertProfileAddView(CertProfileContextMixin, TemplateView):
    """View to import a Certificate Profile from a .json file."""

    http_method_names = ('get', 'post')

    template_name = 'pki/cert_profiles/config.html'
    success_url = reverse_lazy('pki:cert_profiles')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the issued certificates to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data()

        Returns:
            The context to render the page.
        """
        context = super().get_context_data(**kwargs)
        context['profile'] = {'unique_name': ''}
        context['profile_json'] = {
            'type': 'cert_profile',
            'subj': {},
            'ext': {},
        }

        return context

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles POST requests to the view.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            An HTTP response redirecting to the success URL.
        """
        del args, kwargs  # Unused
        try:
            json_dict = json.loads(request.POST.get('profile_json'))
            CertProfilePydanticModel.model_validate(json_dict)
            cert_profile = CertificateProfileModel()
            if request.POST.get('unique_name'):
                cert_profile.unique_name = request.POST.get('unique_name')
            cert_profile.profile_json = json.dumps(json_dict)
            cert_profile.save()
            messages.success(
                self.request,
                _('Successfully added Certificate Profile {name}.').format(name=cert_profile.unique_name),
            )
        except ValidationError as exc:
            messages.error(request, _('Error updating Certificate Profile: ') + str(exc))
        return HttpResponseRedirect(self.success_url)

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

class CertProfileViewSet(viewsets.ModelViewSet):
    """ViewSet for managing Certificate Profile instances.

    Supports standard CRUD operations such as list, retrieve,
    create, update, and delete.
    """
    queryset = CertificateProfileModel.objects.all().order_by('-created_at')
    serializer_class = CertProfileSerializer
    permission_classes: ClassVar = [IsAuthenticated]
    filter_backends: ClassVar = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter
    ]
    filterset_fields: ClassVar = ['unique_name', 'created_at']
    search_fields: ClassVar = ['unique_name', 'display_name']
    ordering_fields: ClassVar = ['unique_name', 'created_at']

    action_descriptions: ClassVar[dict[str, str]] = {
        'list': 'Retrieve a list of all certificate profiles.',
        'retrieve': 'Retrieve a single certificate profiles by id.',
        'create': 'Create a new certificate profiles .',
        'update': 'Update an existing certificate profiles.',
        'partial_update': 'Partially update an existing certificate profiles.',
        'destroy': 'Delete a certificate profiles.',
    }

    def get_view_description(self, *, html: bool = False) -> str:
        """Return a description for the given action."""
        if hasattr(self, 'action') and self.action in self.action_descriptions:
            return self.action_descriptions[self.action]
        return super().get_view_description(html)

