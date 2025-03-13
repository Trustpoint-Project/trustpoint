"""Contains some global views that are not specific to a single app.

This module contains some general redirect and error views (e.g. 404) as well as specific mixins and view classes
which can be used within the apps.
"""

from __future__ import annotations

import functools
import logging
import traceback
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar, cast

from django.core.exceptions import ImproperlyConfigured
from django.db.models import Model, QuerySet
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic.base import ContextMixin, RedirectView
from django.views.generic.edit import FormMixin
from django.views.generic.list import BaseListView, ListView, MultipleObjectTemplateResponseMixin

if TYPE_CHECKING:

    from django import forms as dj_forms

F = TypeVar('F', bound=Callable[..., Any])

class IndexView(RedirectView):
    """View that redirects to the index home page."""

    permanent: bool = False
    pattern_name: str = 'home:dashboard'


class ListInDetailView(ListView[Model]):
    """Helper view that combines a DetailView and a ListView.

    This is useful for displaying a list within a DetailView.
    Note that 'model' and 'context_object_name' refer to the ListView.
    Use 'detail_model' and 'detail_context_object_name' for the DetailView.
    """

    detail_context_object_name = 'object'
    object: Model

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handles GET requests by retrieving the object."""
        self.object = self.get_object()
        return super().get(*args, **kwargs)

    def get_queryset_for_object(self) -> QuerySet[Any]:
        """Returns the queryset for the detail object."""
        return self.detail_model.objects.all() # type: ignore[no-any-return, attr-defined]

    def get_object(self) -> Any:
        """Retrieves the object based on the primary key in the URL."""
        queryset = self.get_queryset_for_object()
        pk = self.kwargs.get('pk')
        if pk is None:
            exc_msg = 'detail object pk expected in url'
            raise AttributeError(exc_msg)
        return get_object_or_404(queryset, pk=pk)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the detail object to the context."""
        context = super().get_context_data(**kwargs)
        context[self.detail_context_object_name] = self.object
        return context


class SortableTableMixin(ContextMixin):
    """Adds utility for sorting a ListView query by URL parameters.

    default_sort_param must be set in the view to specify default sorting order.
    """
    model: type[Model]
    queryset: QuerySet[Any]
    request: HttpRequest
    default_sort_param: str

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

    def get_queryset(self) -> QuerySet[Any]:
        """Returns a sorted queryset based on URL parameters."""
        if hasattr(self, 'queryset') and self.queryset is not None:
            queryset = self.queryset
        else:
            queryset = self.model.objects.all() # type:ignore[attr-defined]

        # Get sort parameter (e.g., "name" or "-name")
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        if isinstance(queryset, QuerySet):
            if hasattr(self.model, 'is_active'):
                return queryset.order_by('-is_active', sort_param)
            return queryset.order_by(sort_param)
        if isinstance(queryset, list):
            return self._sort_list_of_dicts(queryset, sort_param)

        exc_msg = f'Unknown queryset type: {type}'
        raise TypeError(exc_msg)

    def get_context_data(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data.

        Returns:
            dict[str, Any]: context
        """
        context = super().get_context_data(*args, **kwargs)

        # Get current sorting column
        sort_param = self.request.GET.get('sort', self.default_sort_param)

        # Pass sorting details to the template
        context['current_sort'] = sort_param
        return context


class ContextDataMixin:
    """Mixin for context data."""
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
        return cast(dict[str, Any], super_get_context_method(**kwargs))


class BulkDeletionMixin:
    """Mixin for bulk deletion."""
    queryset: Any
    get_queryset: Callable[..., Any]
    success_url: str | None = None

    def delete(self, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Override delete method to redirect after succesfull delete."""
        self.queryset = self.get_queryset()
        success_url = self.get_success_url()
        self.queryset.delete()
        return HttpResponseRedirect(success_url)

    def post(self, request: HttpRequest, *args: tuple[Any], **kwargs: dict[str, Any]) -> HttpResponse:
        """Redirect post method to delete method."""
        return self.delete(request, *args, **kwargs)

    def get_success_url(self) -> str:
        """Return success url."""
        if self.success_url:
            return str(self.success_url)

        exc_msg = 'No URL to redirect to. Provide a success_url.'
        raise ImproperlyConfigured(exc_msg)



class BaseBulkDeleteView(BulkDeletionMixin, FormMixin[Any], BaseListView[Any]):
    """Base view for bulk deletion of objects."""

    def post(self, *_args: Any, **_kwargs: Any) -> HttpResponse:
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


class PrimaryKeyListFromPrimaryKeyString:
    """Helper class to parse a primary key string into a list of unique primary keys."""

    @staticmethod
    def get_pks_as_list(pks: str) -> list[str]:
        """Converts a primary key string into a list of unique primary keys."""
        if pks:
            pks_list = pks.split('/')

            # removing possible trailing empty string
            if pks_list[-1] == '':
                del pks_list[-1]

            if len(pks_list) != len(set(pks_list)):
                msg = 'Duplicates in query primary key list found.'
                raise Http404(msg)

            return pks_list

        return []


class PrimaryKeyQuerysetFromUrlMixin(PrimaryKeyListFromPrimaryKeyString):
    """Mixin to filter a queryset based on primary keys extracted from the URL."""
    queryset: QuerySet[Any] | None = None
    model: type[Model] | None = None

    def get_pks_path(self) -> str:
        """Retrieves the primary key path from URL parameters."""
        if not hasattr(self, 'kwargs') or not isinstance(self.kwargs, dict):
            msg = 'self.kwargs not found' if not hasattr(self, 'kwargs') \
                else f'self.kwargs is not of type dict {type(self.kwargs)}'
            raise TypeError(msg)
        return cast(str, self.kwargs.get('pks', ''))

    def get_queryset(self) -> QuerySet[Any]:
        """Gets the queryset."""
        if self.queryset:
            return self.queryset

        if self.model is None:
            msg = 'No model specified for PrimaryKeyQuerysetFromUrlMixin'
            raise ImproperlyConfigured(msg)

        pks = self.get_pks_as_list(self.get_pks_path())
        if not pks:
            return cast(QuerySet[Any], self.model.objects.all()) # type: ignore[attr-defined]
        queryset = cast(QuerySet[Any], self.model.objects.filter(pk__in=pks)) # type: ignore[attr-defined]

        if len(pks) != len(queryset):
            queryset = self.model.objects.none() # type: ignore[attr-defined]

        self.queryset = queryset
        return queryset


class BulkDeleteView(MultipleObjectTemplateResponseMixin, PrimaryKeyQuerysetFromUrlMixin, BaseBulkDeleteView):
    """View for bulk deletion of objects."""


class LoggerMixin:
    """Mixin that adds log features to the subclass."""

    logger: logging.Logger

    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Adds an appropriate logger to the subclass and makes it available through cls.logger."""
        super().__init_subclass__(**kwargs)

        cls.logger = logging.getLogger('trustpoint').getChild(cls.__module__).getChild(cls.__name__)

    @staticmethod
    def log_exceptions(function: F) -> F:
        """Decorator that gets an appropriate logger and logs any unhandled exception.

        Logs the type and message to both levels error and debug.
        Also adds the traceback to the debug level log.

        Args:
            function: The decorated method or function.
        """

        @functools.wraps(function)
        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except Exception as exception:
                logger = logging.getLogger('trustpoint').getChild(function.__module__).getChild(function.__qualname__)
                msg = f'Exception in {function.__name__}. Type: {type(exception)}, Message: {exception}'
                logger.exception(msg)
                msg = (
                    f'Exception in {function.__name__}. '
                    f'Type: {type(exception)}, '
                    f'Message: {exception}, '
                    f'Traceback: {traceback.format_exc()}'
                )
                logger.debug(msg)
                raise

        return cast(F, _wrapper)
