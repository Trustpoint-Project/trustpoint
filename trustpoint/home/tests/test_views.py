"""Test cases for home app views."""

from datetime import timedelta
from unittest.mock import Mock, patch

from devices.models import DeviceModel
from django.core.management.base import CommandError
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from pki.models import CertificateModel, CertificateProfileModel, CaModel, IssuedCredentialModel

from ..views import (
    AddDomainsAndDevicesView,
    DashboardChartsAndCountsView,
    DashboardView,
    IndexView,
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

    def test_template_name(self) -> None:
        """Test that DashboardView uses the correct template."""
        view = DashboardView()
        assert view.template_name == 'home/dashboard.html'

    def test_get_context_data(self) -> None:
        """Test that get_context_data returns correct page context."""
        request = self.factory.get(self.url)
        view = DashboardView()
        view.request = request
        view.kwargs = {}
        context = view.get_context_data()
        assert context['page_category'] == 'home'
        assert context['page_name'] == 'dashboard'


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
        assert b'Invalid start_date format' in response.content

    def test_get_with_start_date_after_end_date(self) -> None:
        """Test GET with an invalid date range."""
        request = self.factory.get('/dashboard_data/', {'start_date': '2026-04-15', 'end_date': '2026-04-01'})

        response = self.view.get(request)

        assert response.status_code == 400
        assert b'start_date must be on or before end_date' in response.content

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
                'expiring_in_30_days': 3,
            }
            result = self.view.get_cert_counts()

        assert result['total'] == 10
        assert result['active'] == 8
        assert result['expired'] == 2
        assert result['expiring_in_30_days'] == 3

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

        assert 'expiring_in_1_day' in result
        assert 'expiring_in_7_days' in result
        assert 'expiring_in_30_days' in result

    def test_get_expired_or_revoked_device_counts(self) -> None:
        """Test get_expired_or_revoked_device_counts method."""
        with patch('home.views.filter_expired_or_revoked_devices') as mock_filter_expired_devices:
            mock_filter_expired_devices.return_value.count.return_value = 2
            result = self.view.get_expired_or_revoked_device_counts()

        assert 'expired' in result
        assert result['expired'] == 2

    def test_get_expiring_issuing_ca_counts(self) -> None:
        """Test get_expiring_issuing_ca_counts method."""
        with patch.object(CaModel.objects, 'filter') as mock_filter:
            mock_filter.return_value.distinct.return_value.count.return_value = 1
            result = self.view.get_expiring_issuing_ca_counts()

        assert 'expiring_in_1_day' in result
        assert 'expiring_in_7_days' in result
        assert 'expiring_in_30_days' in result
        assert 'expiring_in_365_days' in result

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

    @patch.object(DashboardChartsAndCountsView, 'get_device_enrollment_counts')
    @patch.object(DashboardChartsAndCountsView, 'get_device_domain_credential_counts')
    @patch.object(DashboardChartsAndCountsView, 'get_device_application_certificate_counts')
    @patch.object(DashboardChartsAndCountsView, 'get_expiring_application_certificate_counts')
    @patch.object(DashboardChartsAndCountsView, 'get_device_count_by_onboarding_protocol')
    @patch.object(DashboardChartsAndCountsView, 'get_device_count_by_domain')
    def test_get_device_charts_data(
        self,
        mock_domain: Mock,
        mock_protocol: Mock,
        mock_expiring_application_certificates: Mock,
        mock_application_certificates: Mock,
        mock_domain_credentials: Mock,
        mock_enrollment: Mock,
    ) -> None:
        """Test get_device_charts_data method."""
        mock_enrollment.return_value = {'total': 10}
        mock_domain_credentials.return_value = {'total': 7}
        mock_application_certificates.return_value = {'total': 4}
        mock_expiring_application_certificates.return_value = {'expiring_in_1_day': 1, 'expiring_in_7_days': 2}
        mock_protocol.return_value = {'CMP': 5}
        mock_domain.return_value = [{'domain_name': 'test', 'count': 10}]

        dashboard_data: dict = {}
        start_date = timezone.now()
        reference_date = timezone.now()

        self.view.get_device_charts_data(dashboard_data, start_date, reference_date)

        assert 'device_enrollment_counts' in dashboard_data
        assert 'device_domain_credential_counts' in dashboard_data
        assert 'device_application_certificate_counts' in dashboard_data
        assert 'expiring_application_certificate_counts' in dashboard_data
        assert 'device_counts_by_op' in dashboard_data
        assert 'device_counts_by_domain' in dashboard_data

    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_status')
    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_profile')
    def test_get_cert_charts_data(
        self,
        mock_profile: Mock,
        mock_status: Mock,
    ) -> None:
        """Test get_cert_charts_data method."""
        mock_status.return_value = {'Valid': 10}
        mock_profile.return_value = {'Default': 10}

        dashboard_data: dict = {}
        start_date = timezone.now()
        end_date = timezone.now()
        reference_date = timezone.now()

        self.view.get_cert_charts_data(dashboard_data, start_date, end_date, reference_date)

        assert 'cert_counts_by_status' in dashboard_data
        assert 'cert_counts_by_profile' in dashboard_data

    @patch.object(DashboardChartsAndCountsView, 'get_cert_counts_by_issuing_ca')
    def test_get_ca_charts_data(
        self,
        mock_ca: Mock,
    ) -> None:
        """Test get_ca_charts_data method."""
        mock_ca.return_value = [{'ca_name': 'test', 'count': 10}]

        dashboard_data: dict = {}
        start_date = timezone.now()
        end_date = timezone.now()

        self.view.get_ca_charts_data(dashboard_data, start_date, end_date)

        assert 'cert_counts_by_issuing_ca' in dashboard_data
