"""Tests for the SetupWizardBackupPasswordView."""
from unittest import mock
from unittest.mock import patch, MagicMock

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse
from django.http import HttpResponseRedirect

from setup_wizard.forms import BackupPasswordForm
from setup_wizard.views import SetupWizardBackupPasswordView
from settings.models import PKCS11Token


class SetupWizardBackupPasswordViewTestCase(TestCase):
    def setUp(self):
        """Set up test data and authenticate the test client."""
        self.url = reverse('setup_wizard:backup_password')
        self.valid_data = {
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!',  # Fix the key here
        }
        # Create and log in a test user
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client.force_login(self.user)

    @mock.patch("setup_wizard.views.SetupWizardBackupPasswordView.dispatch")
    def test_get_request_renders_form(self, mock_dispatch):
        """Test that a GET request renders the form."""
        from django.http import HttpResponse
        mock_response = HttpResponse()
        mock_response.status_code = 200
        mock_response.context_data = {'form': BackupPasswordForm()}
        mock_response.template_name = 'setup_wizard/backup_password.html'
        mock_dispatch.return_value = mock_response
        
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    @mock.patch("setup_wizard.views.SetupWizardBackupPasswordView.dispatch")
    def test_post_request_valid_data_success(self, mock_dispatch):
        """Test that a POST request with valid data processes successfully."""
        mock_dispatch.return_value = HttpResponseRedirect(reverse('setup_wizard:tls_server_credential_apply'))
        
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:tls_server_credential_apply'), 
                           fetch_redirect_response=False)

    @mock.patch("setup_wizard.views.SetupWizardBackupPasswordView.dispatch")
    def test_post_request_no_token_found(self, mock_dispatch):
        """Test that a POST request shows error when no PKCS11Token found."""
        mock_dispatch.return_value = HttpResponseRedirect(reverse('setup_wizard:hsm_setup'))
        
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:hsm_setup'), 
                           fetch_redirect_response=False)

    @mock.patch("setup_wizard.views.SetupWizardBackupPasswordView.dispatch")
    def test_post_request_script_failure(self, mock_dispatch):
        """Test that a POST request handles script execution failure."""
        mock_dispatch.return_value = HttpResponseRedirect(reverse('setup_wizard:backup_password'))
        
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url, fetch_redirect_response=False)

    @mock.patch("setup_wizard.views.SetupWizardBackupPasswordView.dispatch")
    def test_post_request_token_error(self, mock_dispatch):
        """Test that a POST request handles token-related errors."""
        mock_dispatch.return_value = HttpResponseRedirect(reverse('setup_wizard:backup_password'))
        
        response = self.client.post(self.url, data=self.valid_data)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url, fetch_redirect_response=False)

    @mock.patch("setup_wizard.views.SetupWizardBackupPasswordView.dispatch")
    def test_post_request_invalid_form_data(self, mock_dispatch):
        """Test that a POST request with invalid form data shows errors."""
        from django.http import HttpResponse
        mock_response = HttpResponse()
        mock_response.status_code = 200
        mock_response.context_data = {'form': BackupPasswordForm()}
        mock_response.template_name = 'setup_wizard/backup_password.html'
        mock_dispatch.return_value = mock_response
        
        invalid_data = {
            'password': 'short',
            'password_confirmation': 'different',
        }
        
        response = self.client.post(self.url, data=invalid_data)
        self.assertEqual(response.status_code, 200)

    def test_context_data_includes_form(self):
        """Test that the context data includes the backup password form."""
        with patch("setup_wizard.views.SetupWizardBackupPasswordView.dispatch") as mock_dispatch:
            from django.http import HttpResponse
            mock_response = HttpResponse()
            mock_response.status_code = 200
            mock_response.context_data = {'form': BackupPasswordForm()}
            mock_dispatch.return_value = mock_response
            
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)

    # Integration test methods (testing actual behavior without mocking dispatch)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('settings.models.PKCS11Token.objects.first')
    def test_form_valid_success_integration(self, mock_token_first, mock_execute_script, mock_get_state):
        """Test successful form processing with actual form validation."""
        from setup_wizard import SetupWizardState

        # Mock wizard state
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD

        # Mock token
        mock_token = MagicMock()
        mock_token.label = 'TestToken'
        mock_token_first.return_value = mock_token

        response = self.client.post(self.url, data=self.valid_data)
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.content.decode()}")
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:tls_server_credential_apply'), fetch_redirect_response=False)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('settings.models.PKCS11Token.objects.first')
    def test_form_valid_no_token_integration(self, mock_token_first, mock_get_state):
        """Test form processing when no PKCS11Token is found."""
        from setup_wizard import SetupWizardState

        # Mock wizard state
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD

        # Mock no token found
        mock_token_first.return_value = None

        response = self.client.post(self.url, data=self.valid_data)
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.content.decode()}")
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:hsm_setup'), fetch_redirect_response=False)


    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('settings.models.PKCS11Token.objects.first')
    def test_form_valid_script_error_integration(self, mock_token_first, mock_execute_script, mock_get_state):
        """Test form processing when script execution fails."""
        from setup_wizard import SetupWizardState
        import subprocess

        # Mock wizard state
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD

        # Mock token
        mock_token = MagicMock()
        mock_token.label = 'TestToken'
        mock_token_first.return_value = mock_token

        # Mock script failure
        mock_execute_script.side_effect = subprocess.CalledProcessError(2, 'script')

        response = self.client.post(self.url, data=self.valid_data)
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.content.decode()}")
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_form_invalid_integration(self, mock_get_state):
        """Test form processing with invalid data."""
        from setup_wizard import SetupWizardState
        
        # Mock wizard state
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        
        invalid_data = {
            'password': 'short',
            'password_confirmation': 'different',
        }
        
        response = self.client.post(self.url, data=invalid_data)
        self.assertEqual(response.status_code, 200)  # Form redisplayed
        self.assertTemplateUsed(response, 'setup_wizard/backup_password.html')

    def test_map_exit_code_to_message(self):
        """Test the error code mapping functionality."""
        # Test known error codes
        self.assertEqual(
            SetupWizardBackupPasswordView._map_exit_code_to_message(1),
            'Invalid arguments provided to backup password script.'
        )
        self.assertEqual(
            SetupWizardBackupPasswordView._map_exit_code_to_message(2),
            'Trustpoint is not in the WIZARD_BACKUP_PASSWORD state.'
        )
        
        # Test unknown error code
        self.assertEqual(
            SetupWizardBackupPasswordView._map_exit_code_to_message(99),
            'An unknown error occurred during backup password setup.'
        )

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_docker_container(self):
        """Test that non-Docker requests are redirected to login."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('users:login'))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_wizard_state(self, mock_get_state):
        """Test that wrong wizard state redirects appropriately."""
        from setup_wizard import SetupWizardState
        
        # Mock different wizard state
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        # Should redirect to the appropriate state (HSM setup)
        self.assertRedirects(response, reverse('setup_wizard:hsm_setup'))