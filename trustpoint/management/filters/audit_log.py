"""FilterSet for the audit log list view."""

from __future__ import annotations

import django_filters
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _

from management.models.audit_log import AuditLog

User = get_user_model()


class AuditLogFilter(django_filters.FilterSet):
    """FilterSet for the audit log table."""

    operation_type = django_filters.ChoiceFilter(
        choices=AuditLog.OperationType.choices,
        label=_('Operation Type'),
        empty_label=_('All operations'),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    target_content_type = django_filters.ModelChoiceFilter(
        queryset=lambda request: ContentType.objects.filter(  # noqa: ARG005
            id__in=AuditLog.objects.values('target_content_type_id').distinct()
        ),
        label=_('Target Type'),
        empty_label=_('All types'),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    target_object_id = django_filters.CharFilter(
        lookup_expr='exact',
        label=_('Target Object ID'),
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-sm',
            'placeholder': _('Object ID…'),
        }),
    )

    actor = django_filters.ModelChoiceFilter(
        field_name='actor',
        queryset=lambda request: User.objects.filter(  # noqa: ARG005
            id__in=AuditLog.objects.values('actor_id').exclude(actor_id=None).distinct()
        ),
        label=_('Actor'),
        empty_label=_('All users'),
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )

    timestamp_after = django_filters.DateFilter(
        field_name='timestamp',
        lookup_expr='date__gte',
        label=_('From date'),
        widget=forms.DateInput(attrs={
            'class': 'form-control form-control-sm',
            'type': 'date',
        }),
    )

    timestamp_before = django_filters.DateFilter(
        field_name='timestamp',
        lookup_expr='date__lte',
        label=_('To date'),
        widget=forms.DateInput(attrs={
            'class': 'form-control form-control-sm',
            'type': 'date',
        }),
    )

    class Meta:
        """Meta class configuration."""

        model = AuditLog
        fields = (
            'operation_type',
            'target_content_type',
            'target_object_id',
            'actor',
            'timestamp_after',
            'timestamp_before',
        )
