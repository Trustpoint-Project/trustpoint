"""CSV export utilities for Django list views."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.http import HttpResponse

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import Model, QuerySet
    from django.http import HttpRequest


@dataclass
class ExportColumn:
    """Defines a single exportable column for a CSV export."""

    key: str
    label: str
    accessor: Callable[[Any], str] | None = None

    def get_value(self, obj: Any) -> str:
        """Extract the string value for this column from *obj*."""
        if self.accessor is not None:
            return str(self.accessor(obj))
        val: Any = obj
        for part in self.key.split('.'):
            if val is None:
                return ''
            val = getattr(val, part, None)
        return str(val) if val is not None else ''


@dataclass
class ExportConfig:
    """Configuration for exporting a Django queryset to CSV."""

    columns: list[ExportColumn]
    filename: str = 'export'

    @classmethod
    def from_model(
        cls,
        model: type[Model],
        include: list[str] | None = None,
        labels: dict[str, str] | None = None,
        extra: list[ExportColumn] | None = None,
        filename: str = 'export',
    ) -> ExportConfig:
        """Auto-generate an ExportConfig from a Django model's concrete fields."""
        include_set = set(include) if include is not None else None
        _labels = labels or {}

        field_map: dict[str, ExportColumn] = {}
        for field in model._meta.fields:  # noqa: SLF001
            if include_set is not None and field.name not in include_set:
                continue
            label = _labels.get(field.name) or str(field.verbose_name)
            field_map[field.name] = ExportColumn(key=field.name, label=label)

        if include is not None:
            columns: list[ExportColumn] = [field_map[n] for n in include if n in field_map]
        else:
            columns = list(field_map.values())

        columns.extend(extra or [])
        return cls(columns=columns, filename=filename)


def generate_csv_response(
    queryset: QuerySet[Any],
    columns: list[ExportColumn],
    filename: str,
) -> HttpResponse:
    """Generate an HTTP response containing the queryset rows as a CSV file."""
    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
    response['Content-Disposition'] = f'attachment; filename="{filename}.csv"'

    writer = csv.writer(response)
    writer.writerow([col.label for col in columns])

    for obj in queryset:
        writer.writerow([col.get_value(obj) for col in columns])

    return response


class ExportMixin:
    """View mixin that adds CSV export to Django list views."""

    export_config: ExportConfig | None = None

    def get_export_config(self) -> ExportConfig:
        """Return the export configuration for this view."""
        if self.export_config is not None:
            return self.export_config
        model: type[Model] | None = getattr(self, 'model', None)
        if model is not None:
            return ExportConfig.from_model(model)
        msg = (
            f'{self.__class__.__name__} must set export_config, override '
            'get_export_config(), or define a model attribute for auto-discovery.'
        )
        raise NotImplementedError(msg)

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Handle GET requests, short-circuiting to CSV export when requested."""
        if request.GET.get('export') == 'csv':
            return self._handle_csv_export(request)
        parent_get: Callable[..., HttpResponse] | None = getattr(super(), 'get', None)
        if parent_get is None:
            msg = f'{self.__class__.__name__} has no parent get() method in its MRO.'
            raise NotImplementedError(msg)
        return parent_get(request, *args, **kwargs)

    def _handle_csv_export(self, _request: HttpRequest) -> HttpResponse:
        """Build and return the CSV export response."""
        config = self.get_export_config()

        get_queryset: Callable[[], QuerySet[Any]] | None = getattr(self, 'get_queryset', None)
        if get_queryset is None:
            msg = f'{self.__class__.__name__} has no get_queryset() method.'
            raise NotImplementedError(msg)
        queryset = get_queryset()
        return generate_csv_response(queryset, config.columns, config.filename)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Extend the template context with the export configuration."""
        parent_ctx: Callable[..., dict[str, Any]] | None = getattr(super(), 'get_context_data', None)
        context: dict[str, Any] = parent_ctx(**kwargs) if parent_ctx is not None else dict(kwargs)
        context['export_config'] = self.get_export_config()
        return context
