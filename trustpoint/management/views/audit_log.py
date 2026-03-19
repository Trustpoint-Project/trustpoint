"""Audit log views."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.views.generic.list import ListView

from management.filters.audit_log import AuditLogFilter
from management.models.audit_log import AuditLog
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin

if TYPE_CHECKING:
    from django.db.models import QuerySet


class AuditLogListView(PageContextMixin, LoggerMixin, ListView[AuditLog]):
    """Paginated, filterable list view for audit log entries."""

    model = AuditLog
    template_name = 'management/audit_log/list.html'
    context_object_name = 'audit_log_entries'
    paginate_by = 50

    page_category = 'management'
    page_name = 'audit_log'

    def get_queryset(self) -> QuerySet[AuditLog]:
        """Return a filtered and pre-fetched queryset."""
        qs = (
            AuditLog.objects.select_related('target_content_type', 'actor')
            .order_by('-timestamp')
        )
        self._filter = AuditLogFilter(self.request.GET, queryset=qs)
        return self._filter.qs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the active filter to the template context."""
        context = super().get_context_data(**kwargs)
        context['filter'] = self._filter
        return context
