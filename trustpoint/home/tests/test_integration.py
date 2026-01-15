"""Integration tests for home app views."""

from datetime import timedelta
from unittest.mock import Mock, patch

from devices.models import DeviceModel
from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

User = get_user_model()


class DashboardIntegrationTests(TestCase):
    """Integration tests for Dashboard view."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_login(self.user)
        self.url = reverse('home:dashboard')

    def test_dashboard_page_loads(self) -> None:
        """Test that dashboard page loads successfully."""
        response = self.client.get(self.url)

        assert response.status_code == 200
        assert 'notifications' in response.context


class DashboardChartsDataIntegrationTests(TestCase):
    """Integration tests for Dashboard Charts and Counts API."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_login(self.user)
        self.url = reverse('home:dashboard_data')

    def test_dashboard_data_returns_json(self) -> None:
        """Test that dashboard data endpoint returns JSON."""
        response = self.client.get(self.url)

        assert response.status_code == 200
        assert response['Content-Type'] == 'application/json'
        data = response.json()
        assert 'device_counts' in data

    def test_dashboard_data_with_start_date(self) -> None:
        """Test dashboard data with start_date parameter."""
        start_date = (timezone.now() - timedelta(days=7)).isoformat()
        response = self.client.get(self.url, {'start_date': start_date})

        assert response.status_code == 200
        data = response.json()
        assert 'device_counts' in data

    def test_dashboard_data_with_invalid_date(self) -> None:
        """Test dashboard data with invalid date format."""
        response = self.client.get(self.url, {'start_date': 'invalid-date'})

        assert response.status_code == 400
        data = response.json()
        assert 'error' in data
        assert 'Invalid date format' in data['error']

    @patch.object(DeviceModel.objects, 'filter')
    def test_dashboard_data_with_exception(self, mock_filter: Mock) -> None:
        """Test that exceptions are handled gracefully."""
        mock_filter.side_effect = Exception('Database error')

        response = self.client.get(self.url)

        # Should still return 200 with empty data
        assert response.status_code == 200
        data = response.json()
        assert 'device_counts' in data


class IndexViewIntegrationTests(TestCase):
    """Integration tests for Index view."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_login(self.user)

    def test_index_redirects_to_dashboard(self) -> None:
        """Test that index redirects to dashboard."""
        url = reverse('home:index')
        response = self.client.get(url)

        assert response.status_code == 302  # Redirect
        assert response.url == reverse('home:dashboard')
