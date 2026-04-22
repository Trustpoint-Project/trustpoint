"""Tests for users views."""

from __future__ import annotations

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, TestCase
from django.urls import reverse

from users.views import TrustpointLoginView

User = get_user_model()


class TrustpointLoginViewTest(TestCase):
    """Test suite for the simplified login view."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.login_url = reverse('users:login')
        self.user = User.objects.create_user(username='testuser', password='testpass123')

    def _attach_messages(self, request) -> None:
        request.session = self.client.session
        request._messages = FallbackStorage(request)

    def test_http_method_names(self) -> None:
        """Only GET and POST should be allowed."""
        self.assertEqual(TrustpointLoginView.http_method_names, ('get', 'post'))

    @patch('users.views.messages.get_messages')
    def test_get_clears_messages_and_renders_login(self, mock_get_messages: Mock) -> None:
        """GET should drain messages before rendering the login page."""
        mock_get_messages.return_value = []
        request = self.factory.get(self.login_url)
        request.user = Mock()
        self._attach_messages(request)

        view = TrustpointLoginView()
        view.setup(request)

        response = view.get(request)

        mock_get_messages.assert_called_once_with(request)
        self.assertEqual(response.status_code, 200)

    @patch('users.views.messages.get_messages')
    @patch('users.views.LoginView.post')
    def test_post_clears_messages_and_delegates(self, mock_super_post: Mock, mock_get_messages: Mock) -> None:
        """POST should drain messages and then delegate to Django's LoginView."""
        mock_get_messages.return_value = []
        mock_super_post.return_value = Mock(status_code=302)

        request = self.factory.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'},
        )
        request.user = Mock()
        self._attach_messages(request)

        view = TrustpointLoginView()
        view.setup(request)

        response = view.post(request)

        mock_get_messages.assert_called_once_with(request)
        mock_super_post.assert_called_once()
        self.assertEqual(response.status_code, 302)
