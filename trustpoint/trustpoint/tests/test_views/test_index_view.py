"""Tests for the IndexView class."""

from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase
from django.urls import resolve, reverse
from home.views import IndexView


class TestIndexView(TestCase):
    """Test cases for the IndexView."""

    def setUp(self) -> None:
        """Set up test environment, including a test user and request factory."""
        self.user = User.objects.create_user(username='testuser', password='password')  # noqa: S106
        self.factory = RequestFactory()

    def test_index_view_redirection_authenticated(self) -> None:
        """Test that IndexView redirects an authenticated user to the expected URL."""
        request = self.factory.get('/')
        request.user = self.user

        view = IndexView.as_view()
        response = view(request)

        assert response.status_code == 302, 'Response should return status 302 for temporary redirection.'  # noqa: PLR2004

        expected_url = reverse('home:dashboard')
        assert response.url == expected_url, f"IndexView should redirect to '{expected_url}'."

    def test_index_view_url_resolves_correctly(self) -> None:
        """Test that the IndexView resolves to the correct view class."""
        view = resolve(reverse('home:index'))

        assert view.func.view_class == IndexView, 'The resolved view should be IndexView.'
