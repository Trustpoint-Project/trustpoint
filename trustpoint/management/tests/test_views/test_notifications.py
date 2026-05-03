"""Test cases for notification views in the management app."""

from datetime import UTC, datetime
from unittest.mock import Mock, patch

from django.test import RequestFactory, TestCase

from management.models import NotificationModel, NotificationStatus
from management.views.notifications import (
    NotificationDetailsView,
    NotificationMarkSolvedView,
    NotificationsListView,
)


class NotificationsListViewTests(TestCase):
    """Test cases for NotificationsListView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_render_created_at_with_new_status(self) -> None:
        """Test _render_created_at with NEW status."""
        notification = Mock()
        notification.created_at = datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC)
        notification.statuses.filter.return_value.exists.return_value = True

        result = NotificationsListView._render_created_at(notification)  # noqa: SLF001

        assert '2025-01-15 10:30:00' in str(result)
        assert 'badge' in str(result)
        assert 'New' in str(result)

    def test_render_created_at_without_new_status(self) -> None:
        """Test _render_created_at without NEW status."""
        notification = Mock()
        notification.created_at = datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC)
        notification.statuses.filter.return_value.exists.return_value = False

        result = NotificationsListView._render_created_at(notification)  # noqa: SLF001

        assert '2025-01-15 10:30:00' in str(result)
        assert 'badge' not in str(result).lower()

    def test_render_notification_type_critical(self) -> None:
        """Test _render_notification_type for CRITICAL notification."""
        notification = Mock()
        notification.notification_type = NotificationModel.NotificationTypes.CRITICAL
        notification.get_notification_type_display.return_value = 'Critical'

        result = NotificationsListView._render_notification_type(notification)  # noqa: SLF001

        assert 'badge' in str(result)
        assert 'bg-danger' in str(result)
        assert 'Critical' in str(result)

    def test_render_notification_type_warning(self) -> None:
        """Test _render_notification_type for WARNING notification."""
        notification = Mock()
        notification.notification_type = NotificationModel.NotificationTypes.WARNING
        notification.get_notification_type_display.return_value = 'Warning'

        result = NotificationsListView._render_notification_type(notification)  # noqa: SLF001

        assert 'badge' in str(result)
        assert 'bg-warning' in str(result)

    def test_render_notification_type_info(self) -> None:
        """Test _render_notification_type for INFO notification."""
        notification = Mock()
        notification.notification_type = NotificationModel.NotificationTypes.INFO
        notification.get_notification_type_display.return_value = 'Info'

        result = NotificationsListView._render_notification_type(notification)  # noqa: SLF001

        assert 'badge' in str(result)
        assert 'bg-info' in str(result)


class NotificationDetailsViewTests(TestCase):
    """Test cases for NotificationDetailsView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('management.views.notifications.NotificationStatus.objects.get_or_create')
    def test_get_context_data_removes_new_status(self, mock_get_or_create: Mock) -> None:
        """Test that get_context_data sets is_read based on NEW status presence."""
        new_status = Mock(spec=NotificationStatus)
        solved_status = Mock(spec=NotificationStatus)
        mock_get_or_create.side_effect = [
            (new_status, False),
            (solved_status, False),
        ]

        notification = Mock(spec=NotificationModel)
        notification.statuses.all.return_value = [new_status]
        notification.statuses.values_list.return_value = ['NEW']
        notification.device = None
        notification.certificate = None

        view = NotificationDetailsView()
        view.object = notification
        view.kwargs = {}

        context = view.get_context_data()

        assert 'is_solved' in context
        assert 'is_read' in context
        assert context['is_read'] is False  # NEW status is present, so not read

    @patch('management.views.notifications.NotificationStatus.objects.get_or_create')
    def test_get_context_data_is_solved_true(self, mock_get_or_create: Mock) -> None:
        """Test that get_context_data sets is_solved to True when solved status present."""
        new_status = Mock(spec=NotificationStatus)
        solved_status = Mock(spec=NotificationStatus)
        mock_get_or_create.side_effect = [
            (new_status, False),
            (solved_status, False),
        ]

        notification = Mock(spec=NotificationModel)
        notification.statuses.all.return_value = [solved_status]
        notification.statuses.values_list.return_value = ['SOLVED']
        notification.device = None
        notification.certificate = None

        view = NotificationDetailsView()
        view.object = notification
        view.kwargs = {}

        context = view.get_context_data()

        assert context['is_solved'] is True


class NotificationMarkSolvedViewTests(TestCase):
    """Test cases for NotificationMarkSolvedView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('management.views.notifications.NotificationStatus.objects.get_or_create')
    def test_get_context_data_adds_solved_status(self, mock_get_or_create: Mock) -> None:
        """Test that get_context_data adds SOLVED status."""
        solved_status = Mock(spec=NotificationStatus)
        mock_get_or_create.return_value = (solved_status, False)

        notification = Mock(spec=NotificationModel)
        notification.statuses.all.return_value = [solved_status]

        view = NotificationMarkSolvedView()
        view.object = notification
        view.kwargs = {}

        context = view.get_context_data()

        notification.statuses.add.assert_called_once_with(solved_status)
        assert context['is_solved'] is True
