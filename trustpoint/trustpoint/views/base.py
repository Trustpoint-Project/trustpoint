"""Contains some global views that are not specific to a single app.

This module contains some general redirect and error views (e.g. 404) as well as specific mixins and view classes
which can be used within the apps.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast, Protocol, Self

from django import forms as dj_forms
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic.base import RedirectView
from django.views.generic.edit import FormMixin
from django.views.generic.list import BaseListView, ListView, MultipleObjectTemplateResponseMixin

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest


class IndexView(RedirectView):
    """View that redirects to the index home page."""

    permanent: bool = False
    pattern_name: str = 'home:dashboard'


class ListInDetailView(ListView):
    """Helper view that combines a DetailView and a ListView.

    This is useful for displaying a list within a DetailView.
    Note that 'model' and 'context_object_name' refer to the ListView.
    Use 'detail_model' and 'detail_context_object_name' for the DetailView.
    """

    detail_context_object_name = 'object'

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        self.object = self.get_object()
        return super().get(*args, **kwargs)

    def get_queryset_for_object(self):
        return self.detail_model.objects.all()

    def get_object(self) -> models.odel:
        queryset = self.get_queryset_for_object()
        pk = self.kwargs.get('pk')
        if pk is None:
            exc_msg = 'detail object pk expected in url'
            raise AttributeError(exc_msg)
        return get_object_or_404(queryset, pk=pk)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context[self.detail_context_object_name] = self.object
        return context

class SupportsGetContextData(Protocol):
    """For typing to provide super().get_context_data()."""

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ...

class ParentSupportsGetContextData(SupportsGetContextData, Protocol):
    """For typing to provide super().get_context_data()."""


class SortableTableMixin[T: models.Model]:
    """Adds utility for sorting a ListView query by URL parameters.

    default_sort_param must be set in the view to specify default sorting order.
    """

    default_sort_param: str
    request: HttpRequest
    model: T

    def get_queryset(self) -> models.QuerySet[Any]:
        if hasattr(self, 'queryset') and self.queryset is not None:
            queryset = self.queryset
        else:
            queryset = self.model.objects.all()

        sort_param = self.request.GET.get('sort', self.default_sort_param)
        # if issubclass(queryset_type, models.QuerySet):
        if hasattr(self.model, 'is_active'):
            return queryset.order_by('-is_active', sort_param)
        return queryset.order_by(sort_param)


    def get_context_data(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(*args, **kwargs)

        # Get current sorting column
        sort_param = self.request.GET.get('sort', self.default_sort_param)

        # Pass sorting details to the template
        context['current_sort'] = sort_param
        return context


class ContextDataMixin:
    def get_context_data(self, **kwargs: Any) -> dict:
        """Adds attributes prefixed with context_ to the context_data if it does not exist.

        Note:
            If another succeeding class in the MRO has another get_context_data method,
            this method will be called after setting the attributes to the context_data.

        Example:
            Lets consider context_page_category.
            Then the attribute page_category with the value of context_page_category is
            added to the context_data if page_category does not already exist in the context_data.

        Example:
            The following Mixin will add 'page_category': 'pki', and 'page_name': 'endpoint_profiles'
             to the context data.

            class EndpointProfilesExtraContextMixin(ContextDataMixin):
                \"\"\"Mixin which adds context_data for the PKI -> Endpoint Profiles pages.\"\"\"

                context_page_category = 'pki'
                context_page_name = 'endpoint_profiles'
        """
        prefix = 'context_'
        for attr in dir(self):
            if attr.startswith(prefix) and len(attr) > len(prefix):
                kwargs.setdefault(attr[len(prefix) :], getattr(self, attr))

        super_get_context_method = getattr(super(), 'get_context_data', None)
        if super_get_context_method is None:
            return kwargs
        return super_get_context_method(**kwargs)


class BaseBulkDeleteView(FormMixin, BaseListView):
    """Base view for bulk deletion of objects."""

    queryset: Any
    get_queryset: Callable
    success_url = None

    form_class = dj_forms.Form

    def post(self, *_args: tuple[Any], **_kwargs: dict[str, Any]) -> HttpResponse:
        """Handles POST requests to the BulkDeleteView."""
        self.queryset = self.get_queryset()
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        return self.form_invalid(form)

    def form_valid(self, _form: form_class) -> HttpResponse:
        """Delete the selected objects on valid form."""
        success_url = self.get_success_url()
        self.queryset.delete()
        return HttpResponseRedirect(success_url)

    def get_success_url(self) -> str:
        """Returns the URL to redirect to after a successful deletion."""
        if self.success_url:
            return self.success_url

        exc_msg = 'No URL to redirect to. Provide a success_url.'
        raise ImproperlyConfigured(exc_msg)


class PrimaryKeyListFromPrimaryKeyString:
    @staticmethod
    def get_pks_as_list(pks: str) -> list[str]:
        if pks:
            pks_list = pks.split('/')

            # removing possible trailing empty string
            if pks_list[-1] == '':
                del pks_list[-1]

            if len(pks_list) != len(set(pks_list)):
                raise Http404('Duplicates in query primary key list found.')

            return pks_list

        return []


class PrimaryKeyQuerysetFromUrlMixin(PrimaryKeyListFromPrimaryKeyString):
    def get_pks_path(self) -> str:
        return self.kwargs.get('pks')

    def get_queryset(self) -> None | models.QuerySet:
        if self.queryset:
            return self.queryset

        pks = self.get_pks_as_list(self.get_pks_path())
        if not pks:
            return self.model.objects.all()
        queryset = self.model.objects.filter(pk__in=pks)

        if len(pks) != len(queryset):
            queryset = None

        self.queryset = queryset
        return queryset


class BulkDeleteView(MultipleObjectTemplateResponseMixin, PrimaryKeyQuerysetFromUrlMixin, BaseBulkDeleteView):
    pass