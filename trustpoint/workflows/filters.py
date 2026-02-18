"""Filter classes for workflow instances and enrollment requests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import django_filters
from django import forms
from django.utils.translation import gettext_lazy as _

from pki.models import DomainModel
from workflows.models import EnrollmentRequest, State

if TYPE_CHECKING:
    from django.db.models import QuerySet


class EnrollmentRequestFilter(django_filters.FilterSet):
    """Filters for the enrollment request list."""

    device_name = django_filters.CharFilter(
        label=_('Device'),
        field_name='device__common_name',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('Search device…')}),
    )

    include_finalized = django_filters.BooleanFilter(
        label=_('Include finalized/aborted requests'),
        method='filter_include_finalized',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    domain = django_filters.ModelChoiceFilter(
        label=_('Domain'),
        field_name='domain',
        queryset=DomainModel.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    protocol = django_filters.CharFilter(
        label=_('Protocol'),
        field_name='protocol',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('EST, CMP, …')}),
    )

    operation = django_filters.CharFilter(
        label=_('Operation'),
        field_name='operation',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('simpleenroll, …')}),
    )

    template = django_filters.CharFilter(
        label=_('Template'),
        field_name='template',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('Template…')}),
    )

    state = django_filters.ChoiceFilter(
        label=_('State'),
        field_name='aggregated_state',
        choices=State.choices,
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    requested_from = django_filters.DateTimeFilter(
        label=_('Requested from'),
        field_name='created_at',
        lookup_expr='gte',
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control form-control-sm'}),
    )

    requested_to = django_filters.DateTimeFilter(
        label=_('Requested to'),
        field_name='created_at',
        lookup_expr='lte',
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control form-control-sm'}),
    )

    class Meta:
        """Configuration for EnrollmentRequestFilter."""

        model = EnrollmentRequest
        fields: tuple[str, ...] = ()

    def filter_include_finalized(
        self,
        queryset: QuerySet[EnrollmentRequest],
        _name: str,
        value: Any,
    ) -> QuerySet[EnrollmentRequest]:
        """Filter finalized enrollment requests.

        - Unchecked (value is False/None): only non-finalized requests.
        - Checked (value is True): include finalized as well.

        Args:
            queryset: Base queryset of enrollment requests.
            _name: Name of the filter (unused).
            value: Boolean-like value from the filter widget.

        Returns:
            QuerySet[EnrollmentRequest]: Filtered queryset.
        """
        if value:
            return queryset
        return queryset.filter(finalized=False)
