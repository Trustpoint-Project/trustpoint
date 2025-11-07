"""Workflow filters for pending approvals."""

from __future__ import annotations

import django_filters
from django import forms
from django.utils.translation import gettext_lazy as _

from pki.models import DomainModel
from workflows.models import WorkflowInstance, WorkflowDefinition


class WorkflowFilter(django_filters.FilterSet):
    """Filters for the pending workflow instances list."""

    # Device name (EnrollmentRequest → Device.common_name)
    device_name = django_filters.CharFilter(
        label=_('Device'),
        field_name='enrollment_request__device__common_name',
        lookup_expr='icontains',
        widget=forms.TextInput(
            attrs={
                'class': 'form-control form-control-sm',
                'placeholder': _('Search device…'),
            }
        ),
    )

    # Domain (EnrollmentRequest → Domain)
    domain = django_filters.ModelChoiceFilter(
        label=_('Domain'),
        field_name='enrollment_request__domain',     # ← IMPORTANT: go through enrollment_request
        queryset=DomainModel.objects.all(),
        widget=forms.Select(
            attrs={'class': 'form-select form-select-sm'},
        ),
    )

    # Protocol (EnrollmentRequest.protocol)
    protocol = django_filters.CharFilter(
        label=_('Protocol'),
        field_name='enrollment_request__protocol',
        lookup_expr='icontains',
        widget=forms.TextInput(
            attrs={
                'class': 'form-control form-control-sm',
                'placeholder': _('EST, CMP, …'),
            }
        ),
    )

    # Workflow definition (WorkflowInstance.definition)
    workflow = django_filters.ModelChoiceFilter(
        label=_('Workflow'),
        field_name='definition',
        queryset=WorkflowDefinition.objects.all(),
        widget=forms.Select(
            attrs={'class': 'form-select form-select-sm'},
        ),
    )

    # Request time range (WorkflowInstance.created_at)
    requested_from = django_filters.DateTimeFilter(
        label=_('Requested from'),
        field_name='created_at',
        lookup_expr='gte',
        widget=forms.DateTimeInput(
            attrs={
                'type': 'datetime-local',
                'class': 'form-control form-control-sm',
            }
        ),
    )

    requested_to = django_filters.DateTimeFilter(
        label=_('Requested to'),
        field_name='created_at',
        lookup_expr='lte',
        widget=forms.DateTimeInput(
            attrs={
                'type': 'datetime-local',
                'class': 'form-control form-control-sm',
            }
        ),
    )

    class Meta:
        model = WorkflowInstance
        # Do NOT auto-generate extra filters like "domain"
        fields: tuple[str, ...] = ()
