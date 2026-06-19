"""CA views for the PKI application."""

import logging
from typing import Any, cast

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError, QuerySet
from django.forms import Form
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.generic import ListView

from management.models.audit_log import AuditLog
from pki.filters import CaFilter
from pki.models import CaModel
from shared.exports import ExportColumn, ExportConfig, ExportMixin
from trustpoint.views.base import BulkDeleteView, ContextDataMixin

logger = logging.getLogger(__name__)


class CaTableView(ExportMixin, ContextDataMixin, ListView[CaModel]):
    """Table view for all CAs with hierarchy information."""

    model = CaModel
    template_name = 'pki/cas/cas.html'
    context_object_name = 'cas'
    paginate_by = None
    filterset_class = CaFilter

    # Context attributes for sidebar navigation
    context_page_category = 'pki'
    context_page_name = 'cas'

    def get_export_config(self) -> ExportConfig:
        """Return the CSV export configuration for the CA table."""
        return ExportConfig.from_model(
            CaModel,
            include=['unique_name', 'parent_ca', 'is_active', 'created_at'],
            labels={'created_at': _('Created At')},
            extra=[
                ExportColumn(
                    key='ca_type',
                    label=_('Type'),
                    accessor=lambda c: c.get_ca_type_display() if c.ca_type is not None else '-',
                ),
                ExportColumn(
                    key='domains',
                    label=_('Domains'),
                    accessor=lambda c: ', '.join(str(d) for d in c.domains.all()),
                ),
                ExportColumn(
                    key='signature_suite',
                    label=_('Signature Suite'),
                    accessor=lambda c: str(c.signature_suite) if c.signature_suite else '-',
                ),
                ExportColumn(
                    key='not_valid_after',
                    label=_('Not Valid After'),
                    accessor=lambda c: (
                        timezone.localtime(c.display_not_valid_after).strftime('%Y-%m-%d %H:%M:%S')
                        if c.display_not_valid_after else '-'
                    ),
                ),
            ],
            filename='certificate_authorities',
        )

    def apply_filters(self, qs: QuerySet[CaModel]) -> QuerySet[CaModel]:
        """Apply the CaFilter to the given queryset.

        Args:
            qs: The base queryset to filter.

        Returns:
            The filtered queryset according to GET parameters.
        """
        self.filterset = CaFilter(self.request.GET, queryset=qs)
        return cast('QuerySet[CaModel]', self.filterset.qs)

    def get_queryset(self) -> QuerySet[CaModel]:
        """Return CA models with relationships prefetched, respecting active filters."""
        base_qs = (
            super().get_queryset()
            .select_related('parent_ca', 'credential__certificate', 'certificate')
            .prefetch_related('domains')
        )
        return self.apply_filters(base_qs)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add hierarchy information and filter state to the context."""
        context = super().get_context_data(**kwargs)

        context['filter'] = getattr(self, 'filterset', None)
        context['filters_active'] = any(
            self.request.GET.get(k)
            for k in ('unique_name', 'ca_type_group', 'is_active')
        )

        # Handle both paginated and non-paginated cases
        if context.get('page_obj'):
            ca_list = list(context['page_obj'].object_list)
        else:
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

    def form_valid(self, form: Form) -> HttpResponse:  # noqa: ARG002
        """Delete the selected CAs on valid form, handling hierarchical dependencies."""
        queryset = self.get_queryset()
        deleted_count = queryset.count() if queryset else 0

        try:
            cas_to_delete = list(queryset)
            self._delete_cas_hierarchically(cas_to_delete)

            actor = self.request.user if self.request.user.is_authenticated else None
            for ca in cas_to_delete:
                AuditLog.create_entry(
                    operation_type=AuditLog.OperationType.CA_DELETED,
                    target=ca,
                    target_display=f'CA: {ca.unique_name}',
                    actor=actor,
                )

            messages.success(self.request, _('Successfully deleted {count} CA(s).').format(count=deleted_count))
            return HttpResponseRedirect(self.success_url)

        except ProtectedError:
            messages.error(
                self.request,
                _('Cannot delete the selected CA(s) because they are referenced by other objects.'),
            )
            return HttpResponseRedirect(self.success_url)
        except ValidationError as exc:
            messages.error(self.request, exc.message)
            return HttpResponseRedirect(self.success_url)

    def _delete_cas_hierarchically(self, cas: list[CaModel]) -> None:
        """Delete CAs in hierarchical order (children before parents).

        Args:
            cas: List of CA models to delete
        """
        ca_ids_to_delete = {ca.id for ca in cas}

        children_map: dict[int | None, list[CaModel]] = {}
        for ca in cas:
            parent_id = ca.parent_ca.id if ca.parent_ca else None
            if parent_id not in children_map:
                children_map[parent_id] = []
            children_map[parent_id].append(ca)

        deleted_ids: set[int] = set()

        def delete_ca_and_children(ca: CaModel) -> None:
            """Recursively delete a CA and all its children."""
            if ca.id in deleted_ids:
                return

            if ca.id in children_map:
                for child in children_map[ca.id]:
                    delete_ca_and_children(child)

            ca.delete()
            deleted_ids.add(ca.id)

        for ca in cas:
            parent_id = ca.parent_ca.id if ca.parent_ca else None
            if parent_id is None or parent_id not in ca_ids_to_delete:
                delete_ca_and_children(ca)
