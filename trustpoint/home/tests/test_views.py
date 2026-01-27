"""Test cases for home app views."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

from devices.models import DeviceModel, IssuedCredentialModel, OnboardingProtocol, OnboardingStatus
from django.contrib.messages import get_messages
from django.core.management.base import CommandError
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from notifications.models import NotificationModel, NotificationStatus
from pki.models import CertificateModel, CertificateProfileModel, CaModel

from ..views import (
    AddDomainsAndDevicesView,
    DashboardChartsAndCountsView,
    DashboardView,
    IndexView,
    NotificationDetailsView,
    NotificationMarkSolvedView,
)


class IndexViewTests(TestCase):
    """Test cases for IndexView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_index_redirects_to_dashboard(self) -> None:
        """Test that IndexView redirects to dashboard."""
        view = IndexView()
        assert view.pattern_name == 'home:dashboard'
        assert view.permanent is False


class DashboardViewTests(TestCase):
    """Test cases for DashboardView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.url = reverse('home:dashboard')

    def test_generate_last_week_dates(self) -> None:
        """Test that generate_last_week_dates returns 7 dates."""
        dates = DashboardView.generate_last_week_dates()
        assert len(dates) == 7
        # Verify dates are in YYYY-MM-DD format
        for date_str in dates:
            datetime.strptime(date_str, '%Y-%m-%d')

    @patch('home.views.NotificationFilter')
    def test_get_queryset(self, mock_filter: Mock) -> None:
        """Test get_queryset method."""
        request = self.factory.get(self.url)
        mock_qs = Mock()
        mock_filter.return_value.qs = mock_qs

        view = DashboardView()
        view.request = request
        view.kwargs = {}
        result = view.get_queryset()

        # Verify filter was called (don't check exact queryset as it may differ)
        assert mock_filter.called
        assert view.queryset == mock_qs

    def test_render_created_at_with_new_status(self) -> None:
        """Test _render_created_at with NEW status."""
        notification = Mock()
        notification.created_at = datetime(2025, 1, 15, 10, 30, 0)
        notification.statuses.filter.return_value.exists.return_value = True

        result = DashboardView._render_created_at(notification)

        assert '2025-01-15 10:30:00' in str(result)
        assert 'badge' in str(result)
        assert 'New' in str(result)

    def test_render_created_at_without_new_status(self) -> None:
        """Test _render_created_at without NEW status."""
        notification = Mock()
        notification.created_at = datetime(2025, 1, 15, 10, 30, 0)
        notification.statuses.filter.return_value.exists.return_value = False

        result = DashboardView._render_created_at(notification)

        assert '2025-01-15 10:30:00' in str(result)
        assert 'badge' not in str(result).lower()

    def test_render_notification_type_critical(self) -> None:
        """Test _render_notification_type for CRITICAL notification."""
        notification = Mock()
        notification.notification_type = NotificationModel.NotificationTypes.CRITICAL
        notification.get_notification_type_display.return_value = 'Critical'

        result = DashboardView._render_notification_type(notification)

        assert 'badge' in str(result)
        assert 'bg-danger' in str(result)
        assert 'Critical' in str(result)

    def test_render_notification_type_warning(self) -> None:
        """Test _render_notification_type for WARNING notification."""
        notification = Mock()
        notification.notification_type = NotificationModel.NotificationTypes.WARNING
        notification.get_notification_type_display.return_value = 'Warning'

        result = DashboardView._render_notification_type(notification)

        assert 'badge' in str(result)
        assert 'bg-warning' in str(result)

    def test_render_notification_type_info(self) -> None:
        """Test _render_notification_type for INFO notification."""
        notification = Mock()
        notification.notification_type = NotificationModel.NotificationTypes.INFO
        notification.get_notification_type_display.return_value = 'Info'

        result = DashboardView._render_notification_type(notification)

        assert 'badge' in str(result)
        assert 'bg-info' in str(result)


class NotificationDetailsViewTests(TestCase):
    """Test cases for NotificationDetailsView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    @patch('home.views.NotificationStatus.objects.get_or_create')
    def test_get_context_data_removes_new_status(self, mock_get_or_create: Mock) -> None:
        """Test that get_context_data removes NEW status."""
        new_status = Mock(spec=NotificationStatus)
        solved_status = Mock(spec=NotificationStatus)
        mock_get_or_create.side_effect = [
            (new_status, False),
            (solved_status, False),
        ]

        notification = Mock(spec=NotificationModel)
        notification.statuses.all.return_value = [new_status]

        view = NotificationDetailsView()
        view.object = notification
        view.kwargs = {}

        context = view.get_context_data()

        notification.statuses.remove.assert_called_once_with(new_status)
        assert 'is_solved' in context

    @patch('home.views.NotificationStatus.objects.get_or_create')
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

    @patch('home.views.NotificationStatus.objects.get_or_create')
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


class AddDomainsAndDevicesViewTests(TestCase):
    """Test cases for AddDomainsAndDevicesView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.url = reverse('home:dashboard')

    @patch('home.views.call_command')
    @patch('home.views.messages.add_message')
    @patch('home.views.redirect')
    def test_get_success(self, mock_redirect: Mock, mock_add_message: Mock, mock_call_command: Mock) -> None:
        """Test successful execution of add_domains_and_devices command."""
        request = self.factory.get('/add-test-data/')

        view = AddDomainsAndDevicesView()
        view.get(request)

        mock_call_command.assert_called_once_with('add_domains_and_devices')
        mock_add_message.assert_called_once()
        args = mock_add_message.call_args[0]
        assert args[0] == request
        assert args[1] == 25  # SUCCESS
        assert 'Successfully added test data' in args[2]
        mock_redirect.assert_called_once_with('home:dashboard')

    @patch('home.views.call_command')
    @patch('home.views.messages.add_message')
    @patch('home.views.redirect')
    def test_get_command_error(self, mock_redirect: Mock, mock_add_message: Mock, mock_call_command: Mock) -> None:
        """Test handling of CommandError."""
        mock_call_command.side_effect = CommandError('Test data already available')
        request = self.factory.get('/add-test-data/')

        view = AddDomainsAndDevicesView()
        view.get(request)

        mock_add_message.assert_called_once()
        args = mock_add_message.call_args[0]
        assert args[0] == request
        assert args[1] == 40  # ERROR
        assert 'Test data already available' in args[2]
        mock_redirect.assert_called_once_with('home:dashboard')


class DashboardChartsAndCountsViewTests(TestCase):
    """Test cases for DashboardChartsAndCountsView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = DashboardChartsAndCountsView()

    def test_get_with_invalid_date_format(self) -> None:
        """Test GET with invalid date format."""
        request = self.factory.get('/dashboard_data/', {'start_date': 'invalid-date'})

        response = self.view.get(request)

        assert response.status_code == 400
        assert b'Invalid date format' in response.content

    @patch.object(DashboardChartsAndCountsView, 'get_device_count_by_onboarding_status')
    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts')
    @patch.object(DashboardChartsAndCountsView, 'get_issuing_ca_counts')
    def test_get_success(
        self,
        mock_issuing_ca: Mock,
        mock_cert_counts: Mock,
        mock_device_counts: Mock,
    ) -> None:
        """Test successful GET request."""
        mock_device_counts.return_value = {'total': 10}
        mock_cert_counts.return_value = {'total': 20}
        mock_issuing_ca.return_value = {'total': 5}

        request = self.factory.get('/dashboard_data/')

        response = self.view.get(request)

        assert response.status_code == 200
        assert b'device_counts' in response.content
        assert b'cert_counts' in response.content

    def test_get_device_count_by_onboarding_status(self) -> None:
        """Test get_device_count_by_onboarding_status method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(DeviceModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.values.return_value.annotate.return_value = []
            result = self.view.get_device_count_by_onboarding_status(start_date)

        assert isinstance(result, dict)
        assert 'total' in result

    def test_get_cert_counts(self) -> None:
        """Test get_cert_counts method."""
        with patch.object(CertificateModel.objects, 'aggregate') as mock_aggregate:
            mock_aggregate.return_value = {
                'total': 10,
                'active': 8,
                'expired': 2,
                'expiring_in_7_days': 1,
                'expiring_in_1_day': 0,
            }
            result = self.view.get_cert_counts()

        assert result['total'] == 10
        assert result['active'] == 8
        assert result['expired'] == 2

    def test_get_issuing_ca_counts(self) -> None:
        """Test get_issuing_ca_counts method."""
        with patch.object(CaModel.objects, 'aggregate') as mock_aggregate:
            mock_aggregate.return_value = {'total': 5, 'active': 4, 'expired': 1}
            result = self.view.get_issuing_ca_counts()

        assert result['total'] == 5
        assert result['active'] == 4

    def test_get_expiring_device_counts(self) -> None:
        """Test get_expiring_device_counts method."""
        with patch.object(DeviceModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.distinct.return_value.count.return_value = 3
            result = self.view.get_expiring_device_counts()

        assert 'expiring_in_24_hours' in result
        assert 'expiring_in_7_days' in result

    def test_get_expired_device_counts(self) -> None:
        """Test get_expired_device_counts method."""
        with patch.object(DeviceModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.distinct.return_value.count.return_value = 2
            result = self.view.get_expired_device_counts()

        assert 'total_expired' in result
        assert 'expired_in_last_7_days' in result

    def test_get_expiring_issuing_ca_counts(self) -> None:
        """Test get_expiring_issuing_ca_counts method."""
        with patch.object(CaModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.count.return_value = 1
            result = self.view.get_expiring_issuing_ca_counts()

        assert 'expiring_in_24_hours' in result
        assert 'expiring_in_7_days' in result

    def test_get_device_count_by_onboarding_protocol(self) -> None:
        """Test get_device_count_by_onboarding_protocol method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(DeviceModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.values.return_value.annotate.return_value = []
            result = self.view.get_device_count_by_onboarding_protocol(start_date)

        assert isinstance(result, dict)

    def test_get_device_count_by_domain(self) -> None:
        """Test get_device_count_by_domain method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(DeviceModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.values.return_value.annotate.return_value = []
            result = self.view.get_device_count_by_domain(start_date)

        assert isinstance(result, list)

    def test_get_cert_counts_by_status(self) -> None:
        """Test get_cert_counts_by_status method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(CertificateModel.objects, 'filter') as mock_filter:
            mock_filter.return_value = []
            result = self.view.get_cert_counts_by_status(start_date)

        assert isinstance(result, dict)

    def test_get_cert_counts_by_issuing_ca(self) -> None:
        """Test get_cert_counts_by_issuing_ca method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(CertificateModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.filter.return_value.values.return_value.annotate.return_value = []
            result = self.view.get_cert_counts_by_issuing_ca(start_date)

        assert isinstance(result, list)

    def test_get_cert_counts_by_domain(self) -> None:
        """Test get_cert_counts_by_domain method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(IssuedCredentialModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.values.return_value.annotate.return_value = []
            result = self.view.get_cert_counts_by_domain(start_date)

        assert isinstance(result, list)

    def test_get_cert_counts_by_profile(self) -> None:
        """Test get_cert_counts_by_profile method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(CertificateProfileModel.objects, 'all') as mock_all:
            mock_all.return_value = []
            with patch.object(IssuedCredentialModel.objects, 'filter') as mock_filter:
                mock_filter.return_value.values.return_value.annotate.return_value = []
                result = self.view.get_cert_counts_by_profile(start_date)

        assert isinstance(result, dict)

    def test_get_issuing_ca_counts_by_type(self) -> None:
        """Test get_issuing_ca_counts_by_type method."""
        start_date = timezone.now() - timedelta(days=7)

        with patch.object(CaModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.values.return_value.annotate.return_value = []
            result = self.view.get_issuing_ca_counts_by_type(start_date)

        assert isinstance(result, dict)

    @patch.object(DashboardChartsAndCountsView, 'get_device_count_by_onboarding_status')
    @patch.object(DashboardChartsAndCountsView, 'get_device_count_by_onboarding_protocol')
    @patch.object(DashboardChartsAndCountsView, 'get_device_count_by_domain')
    def test_get_device_charts_data(
        self,
        mock_domain: Mock,
        mock_protocol: Mock,
        mock_status: Mock,
    ) -> None:
        """Test get_device_charts_data method."""
        mock_status.return_value = {'total': 10}
        mock_protocol.return_value = {'CMP': 5}
        mock_domain.return_value = [{'domain_name': 'test', 'count': 10}]

        dashboard_data: dict = {}
        start_date = timezone.now()

        self.view.get_device_charts_data(dashboard_data, start_date)

        assert 'device_counts_by_os' in dashboard_data
        assert 'device_counts_by_op' in dashboard_data
        assert 'device_counts_by_domain' in dashboard_data

    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_status')
    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_domain')
    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_profile')
    def test_get_cert_charts_data(
        self,
        mock_profile: Mock,
        mock_domain: Mock,
        mock_status: Mock,
    ) -> None:
        """Test get_cert_charts_data method."""
        mock_status.return_value = {'Valid': 10}
        mock_domain.return_value = [{'domain_name': 'test', 'count': 10}]
        mock_profile.return_value = {'Default': 10}

        dashboard_data: dict = {}
        start_date = timezone.now()

        self.view.get_cert_charts_data(dashboard_data, start_date)

        assert 'cert_counts_by_status' in dashboard_data
        assert 'cert_counts_by_domain' in dashboard_data
        assert 'cert_counts_by_profile' in dashboard_data

    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_issuing_ca')
    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_issuing_ca_and_date')
    @patch.object(DashboardChartsAndCountsView, 'get_issuing_ca_counts_by_type')
    def test_get_ca_charts_data(
        self,
        mock_type: Mock,
        mock_ca_date: Mock,
        mock_ca: Mock,
    ) -> None:
        """Test get_ca_charts_data method."""
        mock_ca.return_value = [{'ca_name': 'test', 'count': 10}]
        mock_ca_date.return_value = [{'ca_name': 'test', 'date': '2025-01-01', 'count': 10}]
        mock_type.return_value = {'Root': 1}

        dashboard_data: dict = {}
        start_date = timezone.now()

        self.view.get_ca_charts_data(dashboard_data, start_date)

        assert 'cert_counts_by_issuing_ca' in dashboard_data
        assert 'cert_counts_by_issuing_ca_and_date' in dashboard_data
        assert 'ca_counts_by_type' in dashboard_data
