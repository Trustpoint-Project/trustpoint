"""CA views for the PKI application."""

import logging
from typing import Any

from django.db.models import QuerySet
from django.views.generic import ListView

from pki.models import CaModel
from trustpoint.settings import UIConfig

logger = logging.getLogger(__name__)


class CaTableView(ListView):
    """Table view for all CAs with hierarchy information."""

    model = CaModel
    template_name = 'pki/cas/cas.html'
    context_object_name = 'cas'
    paginate_by = UIConfig.paginate_by

    def get_queryset(self) -> QuerySet[CaModel]:
        """Return all CA models with parent relationships and domains prefetched, ordered by hierarchy."""
        queryset = (super().get_queryset()
                   .select_related('parent_ca', 'issuing_ca_ref')
                   .prefetch_related('issuing_ca_ref__domains'))

        return queryset.order_by('parent_ca__id', 'unique_name')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add hierarchy information to each CA and apply hierarchical ordering."""
        context = super().get_context_data(**kwargs)

        if 'page_obj' in context and context['page_obj'].object_list:
            ca_list = list(context['page_obj'].object_list)
            ca_list = self._hierarchical_sort(ca_list)
            context['page_obj'].object_list = ca_list

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
