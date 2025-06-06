from django.test import TestCase
from django.urls import reverse, resolve
from trustpoint.views.base import IndexView
from django.contrib.auth.models import User


class TestIndexView(TestCase):
    """Test cases for the IndexView."""

    def setUp(self):
        """Create a test user for authentication."""
        self.user = User.objects.create_user(username='testuser', password='password')

    def test_index_view_redirection_authenticated(self):
        """Test that IndexView redirects an authenticated user to the expected URL."""
        self.client.login(username='testuser', password='password')

        response = self.client.get('/')

        self.assertEqual(response.status_code, 302, "Response should return status 302 for temporary redirection.")

        expected_url = reverse('home:dashboard')
        self.assertEqual(response.url, expected_url, f"IndexView should redirect to '{expected_url}'.")



    def test_index_view_url_resolves_correctly(self):
        """Test that the IndexView resolves the correct view class."""
        # Resolve the root URL (IndexView is mapped to `/`)
        view = resolve('/')

        # Verify that it matches the `IndexView` class
        self.assertEqual(
            view.func.view_class,
            IndexView,
            "The resolved view should be IndexView."
        )