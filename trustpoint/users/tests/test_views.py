"""Tests for users views."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse
from setup_wizard import SetupWizardState

from users.views import TrustpointLoginView

if TYPE_CHECKING:
    pass

User = get_user_model()


class TrustpointLoginViewTest(TestCase):
    """Test suite for TrustpointLoginView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = TrustpointLoginView()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.login_url = reverse('users:login')

    @patch('users.views.DOCKER_CONTAINER', False)
    def test_get_non_docker_environment(self) -> None:
        """Test GET request in non-Docker environment bypasses wizard."""
        request = self.factory.get(self.login_url)
        request.user = Mock()
        
        # Setup view with request
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.get(request)
        
        # Should return login page (status 200)
        self.assertEqual(response.status_code, 200)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    def test_get_docker_wizard_completed(
        self,
        mock_get_state: Mock
    ) -> None:
        """Test GET request when wizard is completed."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get(self.login_url)
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.get(request)
        
        # Should return login page
        self.assertEqual(response.status_code, 200)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    @patch('users.views.StartupWizardRedirect.redirect_by_state')
    def test_get_docker_wizard_not_completed(
        self,
        mock_redirect: Mock,
        mock_get_state: Mock
    ) -> None:
        """Test GET request when wizard is not completed."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        mock_redirect.return_value = Mock(status_code=302, url='/wizard/mode/')
        
        request = self.factory.get(self.login_url)
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.get(request)
        
        # Should redirect to wizard
        mock_redirect.assert_called_once_with(SetupWizardState.WIZARD_SETUP_MODE)
        self.assertEqual(response.status_code, 302)

    @patch('users.views.DOCKER_CONTAINER', False)
    @patch('users.views.LoginView.post')
    def test_post_non_docker_environment(self, mock_super_post: Mock) -> None:
        """Test POST request in non-Docker environment bypasses wizard."""
        mock_super_post.return_value = Mock(status_code=302)
        
        request = self.factory.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'}
        )
        request.user = Mock()
        
        # Setup view with request
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.post(request)
        
        # Should call parent post method (bypassing wizard check)
        mock_super_post.assert_called_once()
        self.assertEqual(response.status_code, 302)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    @patch('users.views.LoginView.post')
    def test_post_docker_wizard_completed(
        self,
        mock_super_post: Mock,
        mock_get_state: Mock
    ) -> None:
        """Test POST request when wizard is completed."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_super_post.return_value = Mock(status_code=302)
        
        request = self.factory.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'}
        )
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.post(request)
        
        # Should call parent post method when wizard is complete
        mock_super_post.assert_called_once()
        self.assertEqual(response.status_code, 302)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    @patch('users.views.StartupWizardRedirect.redirect_by_state')
    def test_post_docker_wizard_not_completed(
        self,
        mock_redirect: Mock,
        mock_get_state: Mock
    ) -> None:
        """Test POST request when wizard is not completed."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        mock_redirect.return_value = Mock(status_code=302, url='/wizard/mode/')
        
        request = self.factory.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'}
        )
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.post(request)
        
        # Should redirect to wizard
        mock_redirect.assert_called_once_with(SetupWizardState.WIZARD_SETUP_MODE)
        self.assertEqual(response.status_code, 302)

    def test_http_method_names(self) -> None:
        """Test that only GET and POST methods are allowed."""
        self.assertEqual(TrustpointLoginView.http_method_names, ('get', 'post'))

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    @patch('users.views.messages.get_messages')
    def test_get_clears_messages(
        self,
        mock_get_messages: Mock,
        mock_get_state: Mock
    ) -> None:
        """Test that GET request clears pending messages."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_get_messages.return_value = []
        
        request = self.factory.get(self.login_url)
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.get(request)
        
        # Should clear messages
        mock_get_messages.assert_called_once()
        # Should process normally
        self.assertEqual(response.status_code, 200)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    @patch('users.views.messages.get_messages')
    @patch('users.views.LoginView.post')
    def test_post_clears_messages(
        self,
        mock_super_post: Mock,
        mock_get_messages: Mock,
        mock_get_state: Mock
    ) -> None:
        """Test that POST request clears pending messages."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_get_messages.return_value = []
        mock_super_post.return_value = Mock(status_code=302)
        
        request = self.factory.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'}
        )
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.post(request)
        
        # Should clear messages
        mock_get_messages.assert_called_once()
        # Should call parent post
        mock_super_post.assert_called_once()
        self.assertEqual(response.status_code, 302)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    @patch('users.views.StartupWizardRedirect.redirect_by_state')
    def test_get_wizard_state_setup_hsm(
        self,
        mock_redirect: Mock,
        mock_get_state: Mock
    ) -> None:
        """Test GET with WIZARD_SETUP_HSM wizard state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        mock_redirect.return_value = Mock(status_code=302, url='/wizard/hsm/')
        
        request = self.factory.get(self.login_url)
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.get(request)
        
        # Should redirect to wizard
        mock_redirect.assert_called_once_with(SetupWizardState.WIZARD_SETUP_HSM)
        self.assertEqual(response.status_code, 302)

    @patch('users.views.DOCKER_CONTAINER', True)
    @patch('users.views.SetupWizardState.get_current_state')
    @patch('users.views.StartupWizardRedirect.redirect_by_state')
    def test_post_wizard_state_setup_hsm(
        self,
        mock_redirect: Mock,
        mock_get_state: Mock
    ) -> None:
        """Test POST with WIZARD_SETUP_HSM wizard state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        mock_redirect.return_value = Mock(status_code=302, url='/wizard/hsm/')
        
        request = self.factory.post(
            self.login_url,
            {'username': 'testuser', 'password': 'testpass123'}
        )
        request.user = Mock()
        
        view = TrustpointLoginView()
        view.setup(request)
        
        response = view.post(request)
        
        # Should redirect to wizard
        mock_redirect.assert_called_once_with(SetupWizardState.WIZARD_SETUP_HSM)
        self.assertEqual(response.status_code, 302)
