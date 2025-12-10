"""Test cases for home app filters."""

from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import TestCase
from django.utils import timezone
from notifications.models import NotificationModel

from ..filters import NotificationFilter


class NotificationFilterTests(TestCase):
    """Test cases for NotificationFilter."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.queryset = Mock()

    def test_filter_by_multiple_types_with_value(self) -> None:
        """Test filter_by_multiple_types with comma-separated values."""
        mock_queryset = Mock()
        mock_queryset.filter.return_value = mock_queryset

        result = NotificationFilter.filter_by_multiple_types(mock_queryset, 'field', 'CRITICAL,WARNING')

        mock_queryset.filter.assert_called_once()
        call_kwargs = mock_queryset.filter.call_args[1]
        assert 'notification_type__in' in call_kwargs
        assert call_kwargs['notification_type__in'] == ['CRITICAL', 'WARNING']

    def test_filter_by_multiple_types_without_value(self) -> None:
        """Test filter_by_multiple_types without value."""
        result = NotificationFilter.filter_by_multiple_types(self.queryset, 'field', '')

        assert result == self.queryset

    def test_filter_by_multiple_sources_with_value(self) -> None:
        """Test filter_by_multiple_sources with comma-separated values."""
        mock_queryset = Mock()
        mock_queryset.filter.return_value = mock_queryset

        result = NotificationFilter.filter_by_multiple_sources(mock_queryset, 'field', 'PKI,DEVICE')

        mock_queryset.filter.assert_called_once()
        call_kwargs = mock_queryset.filter.call_args[1]
        assert 'notification_source__in' in call_kwargs
        assert call_kwargs['notification_source__in'] == ['PKI', 'DEVICE']

    def test_filter_by_multiple_sources_without_value(self) -> None:
        """Test filter_by_multiple_sources without value."""
        result = NotificationFilter.filter_by_multiple_sources(self.queryset, 'field', '')

        assert result == self.queryset

    def test_filter_by_date_range_today(self) -> None:
        """Test filter_by_date_range with 'today' value."""
        mock_queryset = Mock()
        mock_queryset.filter.return_value = mock_queryset

        with patch('home.filters.timezone.now') as mock_now:
            mock_now.return_value = timezone.now()
            result = NotificationFilter.filter_by_date_range(mock_queryset, 'field', 'today')

        mock_queryset.filter.assert_called_once()

    def test_filter_by_date_range_last7days(self) -> None:
        """Test filter_by_date_range with 'last7days' value."""
        mock_queryset = Mock()
        mock_queryset.filter.return_value = mock_queryset

        with patch('home.filters.timezone.now') as mock_now:
            mock_now.return_value = timezone.now()
            result = NotificationFilter.filter_by_date_range(mock_queryset, 'field', 'last7days')

        mock_queryset.filter.assert_called_once()

    def test_filter_by_date_range_last30days(self) -> None:
        """Test filter_by_date_range with 'last30days' value."""
        mock_queryset = Mock()
        mock_queryset.filter.return_value = mock_queryset

        with patch('home.filters.timezone.now') as mock_now:
            mock_now.return_value = timezone.now()
            result = NotificationFilter.filter_by_date_range(mock_queryset, 'field', 'last30days')

        mock_queryset.filter.assert_called_once()

    def test_filter_by_date_range_all(self) -> None:
        """Test filter_by_date_range with 'all' value."""
        result = NotificationFilter.filter_by_date_range(self.queryset, 'field', 'all')

        # 'all' returns unfiltered queryset
        assert result == self.queryset

    def test_filter_by_date_range_invalid_value(self) -> None:
        """Test filter_by_date_range with invalid value."""
        result = NotificationFilter.filter_by_date_range(self.queryset, 'field', 'invalid')

        # Invalid values return unfiltered queryset
        assert result == self.queryset

    def test_filter_by_date_range_without_value(self) -> None:
        """Test filter_by_date_range without value."""
        result = NotificationFilter.filter_by_date_range(self.queryset, 'field', '')

        assert result == self.queryset

    def test_filter_meta_configuration(self) -> None:
        """Test that the Meta class is correctly configured."""
        assert NotificationFilter.Meta.model == NotificationModel
        assert 'notification_type' in NotificationFilter.Meta.fields
        assert 'notification_source' in NotificationFilter.Meta.fields
