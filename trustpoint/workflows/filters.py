"""Filter classes for workflow instances and enrollment requests."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import django_filters
from django import forms
from django.utils.translation import gettext_lazy as _
from pki.models import DomainModel

from workflows.models import EnrollmentRequest, State, WorkflowDefinition, WorkflowInstance

if TYPE_CHECKING:
    from django.db.models import QuerySet

STATE_FILTER_CHOICES = (
    (WorkflowInstance.STATE_AWAITING, 'AwaitingApproval'),
    (WorkflowInstance.STATE_APPROVED, 'Approved'),
    (WorkflowInstance.STATE_REJECTED, 'Rejected'),
    (WorkflowInstance.STATE_FAILED, 'Failed'),
    (WorkflowInstance.STATE_ABORTED, 'Aborted'),
)


class WorkflowFilter(django_filters.FilterSet):
    """Filters for the waiting approvals (workflow instances) list."""

    device_name = django_filters.CharFilter(
        label=_('Device'),
        field_name='enrollment_request__device__common_name',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('Search device…')}),
    )

    domain = django_filters.ModelChoiceFilter(
        label=_('Domain'),
        field_name='enrollment_request__domain',
        queryset=DomainModel.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    protocol = django_filters.CharFilter(
        label=_('Protocol'),
        field_name='enrollment_request__protocol',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('EST, CMP, …')}),
    )

    workflow = django_filters.ModelChoiceFilter(
        label=_('Workflow'),
        field_name='definition',
        queryset=WorkflowDefinition.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    state = django_filters.ChoiceFilter(
        label=_('State'),
        field_name='state',
        choices=STATE_FILTER_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    # Works without method because it maps to a real boolean field
    include_finalized = django_filters.BooleanFilter(
        label=_('Include completed/aborted workflows'),
        method='filter_include_finalized',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    # Needs a method: it toggles inclusion/exclusion based on two values on a related field
    include_failed_rejected_parents = django_filters.BooleanFilter(
        label=_('Show rejected/failed requests'),
        method='filter_include_failed_rejected_parents',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
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
        """Configuration for WorkflowFilter."""
        model = WorkflowInstance
        fields: tuple[str, ...] = ()

    def filter_include_failed_rejected_parents(
        self,
        queryset: QuerySet[WorkflowInstance],
        _name: str,
        value: Any,
    ) -> QuerySet[WorkflowInstance]:
        """When unchecked (default), exclude parents in {Rejected, Failed}. When checked, include them."""
        if value:
            return queryset
        return queryset.exclude(
            enrollment_request__aggregated_state__in=[State.REJECTED, State.FAILED]
        )

    def filter_include_finalized(
        self,
        queryset: QuerySet[WorkflowInstance],
        _name: str,
        value: Any,
    ) -> QuerySet[WorkflowInstance]:
        """Semantics.

        - Checkbox unchecked (value is False/None): show only non-finalized.
        - Checkbox checked (value is True): include finalized as well.
        """
        if value:
            # Include both finalized and non-finalized
            return queryset
        # Default: hide completed (finalized=True)
        return queryset.filter(finalized=False)


class EnrollmentRequestFilter(django_filters.FilterSet):
    """Filters for the enrollment request list."""

    device_name = django_filters.CharFilter(
        label=_('Device'),
        field_name='device__common_name',
        lookup_expr='icontains',
        widget=forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': _('Search device…')}),
    )

    include_finalized = django_filters.BooleanFilter(
        label=_('Include completed/aborted requests'),
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
        """Semantics.

        - Unchecked: only non-finalized requests.
        - Checked: include finalized as well.
        """
        if value:
            return queryset
        return queryset.filter(finalized=False)
