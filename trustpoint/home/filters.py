"""Contains custom filter sets to filter model data based on various criteria."""

from datetime import timedelta
from typing import ClassVar

import django_filters
from django.db.models import QuerySet
from django.utils import timezone

from home.models import NotificationModel


class NotificationFilter(django_filters.FilterSet):
    """Filters notifications based on various criteria such as date range and status."""

    notification_type = django_filters.CharFilter(method='filter_by_multiple_types', label='Notification Type')
    notification_source = django_filters.CharFilter(method='filter_by_multiple_sources', label='Notification Source')
    date_range = django_filters.CharFilter(method='filter_by_date_range', label='Date Range')

    class Meta:
        """Configures the filter set's model and fields for filtering."""

        model = NotificationModel
        fields: ClassVar[list] = ['notification_type', 'notification_source']

    def filter_by_multiple_types(self, queryset: QuerySet, _: str, value: str) -> QuerySet:
        """Split the comma-separated values into a list for types"""
        if value:
            types = value.split(',')
            return queryset.filter(notification_type__in=types)
        return queryset

    def filter_by_multiple_sources(self, queryset: QuerySet, _: str, value: str) -> QuerySet:
        """Split the comma-separated values into a list for sources"""
        if value:
            sources = value.split(',')
            return queryset.filter(notification_source__in=sources)
        return queryset

    def filter_by_date_range(self, queryset: QuerySet, _: str, value: str) -> QuerySet:
        """Filter the given QuerySet by date range"""
        now = timezone.now()
        if value == 'today':
            return queryset.filter(created_at__date=now.date())
        if value == 'last7days':
            return queryset.filter(created_at__gte=now - timedelta(days=7))
        if value == 'last30days':
            return queryset.filter(created_at__gte=now - timedelta(days=30))
        if value == 'all':
            return queryset  # No filtering, return all
        return queryset
