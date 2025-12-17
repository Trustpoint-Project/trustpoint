"""Contains some global views that are not specific to a single app.

This module contains some general redirect and error views (e.g. 404) as well as specific mixins and view classes
which can be used within the apps.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from django import forms as dj_forms
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic.base import RedirectView
from django.views.generic.edit import FormMixin
from django.views.generic.list import BaseListView, ListView, MultipleObjectTemplateResponseMixin

from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest
    from django_stubs_ext import StrPromise


class IndexView(RedirectView):
    """View that redirects to the index home page."""

    permanent: bool = False
    pattern_name: str = 'home:dashboard'


class ListInDetailView(ListView[Any]):
    """Helper view that combines a DetailView and a ListView.

    This is useful for displaying a list within a DetailView.
    Note that 'model' and 'context_object_name' refer to the ListView.
    Use 'detail_model' and 'detail_context_object_name' for the DetailView.
    """

    detail_context_object_name = 'object'
    detail_model: type[models.Model]

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        self.object = self.get_object()
        return super().get(*args, **kwargs)

    def get_queryset_for_object(self) -> models.QuerySet[Any, Any]:
        """Get the queryset for the detail object."""
        return self.detail_model.objects.all()  # type: ignore[attr-defined, no-any-return]

    def get_object(self) -> models.Model:
        """Get the detail object from the URL pk parameter."""
        queryset = self.get_queryset_for_object()
        pk = self.kwargs.get('pk')
        if pk is None:
            exc_msg = 'detail object pk expected in url'
            raise AttributeError(exc_msg)
        return get_object_or_404(queryset, pk=pk)  # type: ignore[no-any-return]

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the detail object to the context."""
        context = super().get_context_data(**kwargs)
        context[self.detail_context_object_name] = self.object
        return context

class SupportsGetContextData(Protocol):
    """For typing to provide super().get_context_data()."""

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Get the context data."""
        ...

class ParentSupportsGetContextData(SupportsGetContextData, Protocol):
    """For typing to provide super().get_context_data()."""


class SortableTableMixin[T: models.Model]:
    """Adds utility for sorting a ListView query by URL parameters.

    default_sort_param must be set in the view to specify default sorting order.
    """

    default_sort_param: str
    request: HttpRequest
    model: type[T]
    queryset: models.QuerySet[Any, Any] | None

    def get_queryset(self) -> models.QuerySet[Any, Any]:
        """Get the queryset and apply sorting based on URL parameters."""
        if hasattr(self, 'queryset') and self.queryset is not None:
            queryset = self.queryset
        else:
            queryset = self.model.objects.all()  # type: ignore[attr-defined]

        sort_param = self.request.GET.get('sort', self.default_sort_param)
        if hasattr(self.model, 'is_active'):
            return queryset.order_by('-is_active', sort_param)
        return queryset.order_by(sort_param)


    def get_context_data(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Add sorting information to the context."""
        # Ensure object_list is passed to super() if not already in kwargs
        # This is needed for proper ListView functionality
        if 'object_list' not in kwargs and hasattr(self, 'object_list'):
            kwargs['object_list'] = self.object_list

        context = super().get_context_data(*args, **kwargs)  # type: ignore[misc]

        # Defensive: ensure context is never None
        if context is None:
            context = {}

        # Get current sorting column
        sort_param = self.request.GET.get('sort', self.default_sort_param)

        # Pass sorting details to the template
        context['current_sort'] = sort_param
        return context  # type: ignore[no-any-return]


class SortableTableFromListMixin:
    """Adds utility for sorting a ListView query by URL parameters.

    default_sort_param must be set in the view to specify default sorting order.
    Use instead of SortableTableMixin when you have a list of dicts instead of a Django queryset.
    """
    default_sort_param: str
    request: HttpRequest
    model: type[models.Model]
    queryset: list[dict[str, str]] | None

    @staticmethod
    def _sort_list_of_dicts(list_of_dicts: list[dict[str, Any]], sort_param: str) -> list[dict[str, Any]]:
        """Sorts a list of dictionaries by the given sort parameter.

        Args:
            list_of_dicts: List of dictionaries to sort.
            sort_param: The parameter to sort by. Prefix with '-' for descending order.

        Returns:
            The sorted list of dictionaries.
        """
        return sorted(list_of_dicts, key=lambda x: x[sort_param.lstrip('-')], reverse=sort_param.startswith('-'))

    def get_queryset(self) -> list[dict[str, str]]:
        """Get the queryset and apply sorting based on URL parameters."""
        if hasattr(self, 'queryset') and self.queryset is not None:
            queryset = self.queryset
        else:
            queryset = self.model.objects.all()  # type: ignore[attr-defined]

        # Get sort parameter (e.g., "name" or "-name")
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        return self._sort_list_of_dicts(queryset, sort_param)

    def get_context_data(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Add sorting information to the context."""
        context = super().get_context_data(*args, **kwargs)  # type: ignore[misc]

        # Get current sorting column
        sort_param = self.request.GET.get('sort', self.default_sort_param)

        # Pass sorting details to the template
        context['current_sort'] = sort_param
        return context  # type: ignore[no-any-return]

class ContextDataMixin:
    """Mixin to add context data from attributes prefixed with 'context_'."""

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
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
        return super_get_context_method(**kwargs)  # type: ignore[no-any-return]


class BaseBulkDeleteView(FormMixin[dj_forms.Form], BaseListView[Any]):
    """Base view for bulk deletion of objects."""

    queryset: Any
    get_queryset: Callable[..., models.QuerySet[Any, Any]]
    success_url: str | StrPromise | None = None

    form_class = dj_forms.Form

    def post(self, *_args: tuple[Any], **_kwargs: dict[str, Any]) -> HttpResponse:
        """Handles POST requests to the BulkDeleteView."""
        self.queryset = self.get_queryset()
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        return self.form_invalid(form)

    def form_valid(self, _form: dj_forms.Form) -> HttpResponse:
        """Delete the selected objects on valid form."""
        success_url = self.get_success_url()
        self.queryset.delete()
        return HttpResponseRedirect(success_url)

    def get_success_url(self) -> str:
        """Returns the URL to redirect to after a successful deletion."""
        if self.success_url:
            return self.success_url  # type: ignore[return-value]

        exc_msg = 'No URL to redirect to. Provide a success_url.'
        raise ImproperlyConfigured(exc_msg)


class PrimaryKeyListFromPrimaryKeyString:
    """Utility class to parse primary keys from a URL string."""

    @staticmethod
    def get_pks_as_list(pks: str) -> list[str]:
        """Parse a slash-separated list of primary keys from a URL string."""
        if pks:
            pks_list = pks.split('/')

            # removing possible trailing empty string
            if pks_list[-1] == '':
                del pks_list[-1]

            if len(pks_list) != len(set(pks_list)):
                err_msg = 'Duplicates in query primary key list found.'
                raise Http404(err_msg)

            return pks_list

        return []


class PrimaryKeyQuerysetFromUrlMixin(PrimaryKeyListFromPrimaryKeyString):
    """Mixin to retrieve a queryset based on primary keys provided in the URL."""
    kwargs: dict[str, Any]
    model: type[models.Model]
    queryset: models.QuerySet[Any, Any] | None

    def get_pks_path(self) -> str:
        """Retrieve the primary key path from the URL parameters."""
        return str(self.kwargs.get('pks'))

    def get_queryset(self) -> models.QuerySet[Any, Any]:
        """Retrieve a queryset based on primary keys provided in the URL."""
        if self.queryset:
            return self.queryset

        pks = self.get_pks_as_list(self.get_pks_path())
        if not pks:
            return self.model.objects.all()  # type: ignore[attr-defined, no-any-return]
        queryset = self.model.objects.filter(pk__in=pks)  # type: ignore[attr-defined]

        if len(pks) != len(queryset):
            queryset = self.model.objects.none()  # type: ignore[attr-defined]

        self.queryset = queryset
        return queryset  # type: ignore[no-any-return]


class BulkDeleteView(MultipleObjectTemplateResponseMixin, PrimaryKeyQuerysetFromUrlMixin, BaseBulkDeleteView):
    """View for bulk deletion of objects."""
    model: type[models.Model]


THRESHOLD_LOGGER_HTTP_STATUS: int = 400

class LoggedHttpResponse(HttpResponse, LoggerMixin):
    """Custom HttpResponse that logs and prints error messages automatically."""

    def __init__(self, content: str | bytes = b'', status: int | None = None, *args: Any, **kwargs: Any) -> None:
        """Initialize the LoggedHttpResponse instance.

        Args:
            content (Any): The content of the response.
            status (Optional[int], optional): The HTTP status code of the response. Defaults to None.
            *args (Any): Additional positional arguments passed to HttpResponse.
            **kwargs (Any): Additional keyword arguments passed to HttpResponse.
        """
        if status and status >= THRESHOLD_LOGGER_HTTP_STATUS:
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            self.logger.error('ERROR (%s): %s', status, content)
        else:
            self.logger.info('SUCCESS (%s)', status)

        super().__init__(content, *args, status=status, **kwargs)
