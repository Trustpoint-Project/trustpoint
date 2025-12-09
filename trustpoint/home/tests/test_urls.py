"""Test cases for home app URL configuration."""

from django.test import SimpleTestCase
from django.urls import resolve, reverse

from ..views import (
    AddDomainsAndDevicesView,
    DashboardChartsAndCountsView,
    DashboardView,
    IndexView,
    NotificationDetailsView,
    NotificationMarkSolvedView,
)


class HomeUrlsTests(SimpleTestCase):
    """Test cases for home app URL patterns."""

    def test_index_url_resolves(self) -> None:
        """Test that the index URL resolves to IndexView."""
        url = reverse('home:index')
        assert resolve(url).func.view_class == IndexView

    def test_dashboard_url_resolves(self) -> None:
        """Test that the dashboard URL resolves to DashboardView."""
        url = reverse('home:dashboard')
        assert resolve(url).func.view_class == DashboardView

    def test_notification_details_url_resolves(self) -> None:
        """Test that the notification details URL resolves to NotificationDetailsView."""
        url = reverse('home:notification_details', kwargs={'pk': 1})
        assert resolve(url).func.view_class == NotificationDetailsView

    def test_notification_mark_as_solved_url_resolves(self) -> None:
        """Test that the mark as solved URL resolves to NotificationMarkSolvedView."""
        url = reverse('home:mark_as_solved', kwargs={'pk': 1})
        assert resolve(url).func.view_class == NotificationMarkSolvedView

    def test_dashboard_data_url_resolves(self) -> None:
        """Test that the dashboard data URL resolves to DashboardChartsAndCountsView."""
        url = reverse('home:dashboard_data')
        assert resolve(url).func.view_class == DashboardChartsAndCountsView

    def test_url_names(self) -> None:
        """Test that URL names are correctly set."""
        assert reverse('home:index') == '/home/'
        assert reverse('home:dashboard') == '/home/dashboard/'
        assert reverse('home:notification_details', kwargs={'pk': 1}) == '/home/notification/1/'
        assert reverse('home:mark_as_solved', kwargs={'pk': 1}) == '/home/notification/1/mark-as-solved/'
        assert reverse('home:dashboard_data') == '/home/dashboard_data/'

    def test_app_name(self) -> None:
        """Test that the app namespace is correctly set."""
        url = reverse('home:index')
        assert 'home' in url or url == '/'
