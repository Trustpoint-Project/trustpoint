"""CA views for the PKI application."""

import logging
from typing import Any

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError, QuerySet
from django.forms import Form
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic import ListView

from pki.models import CaModel
from trustpoint.views.base import BulkDeleteView, ContextDataMixin

logger = logging.getLogger(__name__)


class CaTableView(ContextDataMixin, ListView[CaModel]):
    """Table view for all CAs with hierarchy information."""

    model = CaModel
    template_name = 'pki/cas/cas.html'
    context_object_name = 'cas'
    paginate_by = None

    # Context attributes for sidebar navigation
    context_page_category = 'pki'
    context_page_name = 'cas'

    def get_queryset(self) -> QuerySet[CaModel]:
        """Return all CA models with parent relationships and domains prefetched, ordered by hierarchy."""
        return super().get_queryset().select_related('parent_ca').prefetch_related('domains')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add hierarchy information to each CA and apply hierarchical ordering."""
        context = super().get_context_data(**kwargs)

        # Handle both paginated and non-paginated cases
        if context.get('page_obj'):
            # Paginated case
            ca_list = list(context['page_obj'].object_list)
        else:
            # Non-paginated case
            ca_list = list(context.get(self.context_object_name, []))

        if ca_list:
            ca_list = self._hierarchical_sort(ca_list)

            # Add display properties to each CA
            for ca in ca_list:
                ca.display_indentation = f'{ca.get_hierarchy_depth() * 20}px'  # type: ignore[attr-defined]

            if context.get('page_obj'):
                context['page_obj'].object_list = ca_list
            else:
                context[self.context_object_name] = ca_list

        return context

    def _hierarchical_sort(self, cas: list[CaModel]) -> list[CaModel]:
        """Sort CAs hierarchically: roots first, then their children recursively.

        Args:
            cas: List of CA models to sort.

        Returns:
            Hierarchically sorted list of CAs.
        """
        children_map: dict[int | None, list[CaModel]] = {}
        for ca in cas:
            parent_id = ca.parent_ca.id if ca.parent_ca else None
            if parent_id not in children_map:
                children_map[parent_id] = []
            children_map[parent_id].append(ca)

        for children in children_map.values():
            children.sort(key=lambda x: x.unique_name)

        result: list[CaModel] = []

        def add_ca_and_children(parent_id: int | None) -> None:
            """Recursively add CA and its children to result."""
            if parent_id in children_map:
                for ca in children_map[parent_id]:
                    result.append(ca)
                    add_ca_and_children(ca.id)

        add_ca_and_children(None)

        return result


class CaBulkDeleteConfirmView(BulkDeleteView):
    """View to confirm the deletion of multiple CAs."""

    model = CaModel
    success_url = reverse_lazy('pki:cas')
    ignore_url = reverse_lazy('pki:cas')
    template_name = 'pki/cas/confirm_delete.html'
    context_object_name = 'cas'

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests."""
        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, _('No CAs selected for deletion.'))
            return HttpResponseRedirect(self.success_url)
        return super().get(request, *args, **kwargs)

    def form_valid(self, form: Form) -> HttpResponse:
        """Delete the selected CAs on valid form."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            response = super().form_valid(form)
        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected CA(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

        messages.success(self.request, _('Successfully deleted {count} CA(s).').format(count=deleted_count))

        return response
