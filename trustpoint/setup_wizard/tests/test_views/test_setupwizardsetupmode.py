"""Tests for the SetupWizardSetupModeView."""

from unittest.mock import patch

from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.urls import reverse

from setup_wizard import SetupWizardState
from setup_wizard.views import SetupWizardSetupModeView


class SetupWizardSetupModeViewTestCase(TestCase):
    """Test cases for SetupWizardSetupModeView."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.url = reverse('setup_wizard:setup_mode')

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_non_docker_redirects_to_login(self):
        """Test that dispatch redirects to login when not in Docker container."""
        self.client.force_login(self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('users:login'), fetch_redirect_response=False)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_dispatch_wrong_wizard_state_redirects(self, mock_redirect, mock_get_state):
        """Test that dispatch redirects when wizard state is incorrect."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE
        mock_redirect.return_value = HttpResponseRedirect('/redirect/')

        self.client.force_login(self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)
        mock_redirect.assert_called_once_with(SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_dispatch_correct_wizard_state_allows_access(self, mock_get_state):
        """Test that dispatch allows access when wizard state is correct."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        self.client.force_login(self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Setup Mode')

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_get_request_renders_template(self, mock_get_state):
        """Test that a GET request renders the correct template."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        self.client.force_login(self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'setup_wizard/setup_mode.html')

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_only_get_method_allowed(self, mock_get_state):
        """Test that only GET method is allowed."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        self.client.force_login(self.user)

        # Test POST method is not allowed
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 405)  # Method Not Allowed

        # Test PUT method is not allowed
        response = self.client.put(self.url)
        self.assertEqual(response.status_code, 405)  # Method Not Allowed

        # Test DELETE method is not allowed
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 405)  # Method Not Allowed

    def test_view_attributes(self):
        """Test that view has correct attributes."""
        view = SetupWizardSetupModeView()

        self.assertEqual(view.http_method_names, ('get',))
        self.assertEqual(view.template_name, 'setup_wizard/setup_mode.html')

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_inheritance_structure(self, mock_get_state):
        """Test that view properly inherits from TemplateView."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        from django.views.generic import TemplateView

        self.assertTrue(issubclass(SetupWizardSetupModeView, TemplateView))

        view = SetupWizardSetupModeView()
        self.assertTrue(hasattr(view, 'get'))
        self.assertTrue(hasattr(view, 'template_name'))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_context_data_structure(self, mock_get_state):
        """Test that the view provides correct context data."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        self.client.force_login(self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)

        # Verify context contains standard TemplateView context
        self.assertIn('view', response.context)
        self.assertIsInstance(response.context['view'], SetupWizardSetupModeView)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_multiple_wizard_states_redirect_correctly(self, mock_get_state):
        """Test that various incorrect wizard states all redirect properly."""
        with patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state') as mock_redirect:
            mock_redirect.return_value = HttpResponseRedirect('/redirect/')

            test_states = [
                SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE,
                SetupWizardState.WIZARD_SETUP_HSM,
                SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY,
                SetupWizardState.WIZARD_BACKUP_PASSWORD,
                SetupWizardState.WIZARD_DEMO_DATA,
                SetupWizardState.WIZARD_CREATE_SUPER_USER,
                SetupWizardState.WIZARD_COMPLETED,
            ]

            for state in test_states:
                with self.subTest(state=state):
                    mock_get_state.return_value = state

                    self.client.force_login(self.user)
                    response = self.client.get(self.url)

                    self.assertEqual(response.status_code, 302)
                    mock_redirect.assert_called_with(state)

                    # Reset mock for next iteration
                    mock_redirect.reset_mock()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_view_handles_unauthenticated_users(self, mock_get_state):
        """Test that view works for unauthenticated users when conditions are met."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        # Don't force login - test as anonymous user
        response = self.client.get(self.url)

        # View should still render since it doesn't require authentication
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'setup_wizard/setup_mode.html')

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_get_method_behavior(self, mock_get_state):
        """Test that get method properly handles validation and rendering."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        # Test that the get method validates conditions and renders template
        self.client.force_login(self.user)
        response = self.client.get(self.url)

        # Should successfully render the template
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'setup_wizard/setup_mode.html')

        # Verify wizard state was checked
        mock_get_state.assert_called_once()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_view_docstring_accuracy(self, mock_get_state):
        """Test that view behavior matches its docstring description."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        view = SetupWizardSetupModeView()

        # Verify docstring claims are accurate
        self.assertEqual(view.http_method_names, ('get',))
        self.assertEqual(view.template_name, 'setup_wizard/setup_mode.html')

        # Verify it's part of setup wizard process
        self.assertIn('setup_wizard', view.template_name)

        # Verify it validates wizard state (tested in other methods)
        self.assertTrue(hasattr(view, 'get'))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_response_headers_and_status(self, mock_get_state):
        """Test that response has correct headers and status code."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        self.client.force_login(self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/html; charset=utf-8')

        # Verify no redirect headers when state is correct
        self.assertNotIn('Location', response)

    def test_class_level_attributes_immutable(self):
        """Test that class-level attributes are properly defined and immutable."""
        view1 = SetupWizardSetupModeView()
        view2 = SetupWizardSetupModeView()

        # Verify attributes are consistent across instances
        self.assertEqual(view1.http_method_names, view2.http_method_names)
        self.assertEqual(view1.template_name, view2.template_name)

        # Verify they match expected values
        self.assertEqual(view1.http_method_names, ('get',))
        self.assertEqual(view1.template_name, 'setup_wizard/setup_mode.html')

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_wizard_state_validation_order(self, mock_get_state):
        """Test that Docker container check happens before wizard state validation."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        # First test with Docker enabled - should check wizard state
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        mock_get_state.assert_called_once()

        # Reset mock
        mock_get_state.reset_mock()

        # Test with Docker disabled - should not check wizard state
        with patch('setup_wizard.views.DOCKER_CONTAINER', False):
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 302)
            mock_get_state.assert_not_called()
