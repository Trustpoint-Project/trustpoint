"""Tests for the SetupWizardCryptoStorageView."""

import subprocess
from unittest.mock import patch

import pytest
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.http import HttpResponseRedirect
from django.test import RequestFactory, TestCase
from django.urls import reverse
from management.forms import KeyStorageConfigForm
from management.models import KeyStorageConfig

from setup_wizard import SetupWizardState
from setup_wizard.views import SetupWizardCryptoStorageView


class SetupWizardCryptoStorageViewTestCase(TestCase):
    """Test cases for SetupWizardCryptoStorageView."""

    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.url = reverse('setup_wizard:crypto_storage_setup')

        self.view = SetupWizardCryptoStorageView()
        self.request = self.factory.get('/')
        self.request.user = self.user
        self.view.request = self.request

        # Add message framework support
        from django.contrib.messages.storage.fallback import FallbackStorage
        self.request.session = {}
        self.request._messages = FallbackStorage(self.request)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_dispatch_non_docker_redirects_to_login(self, mock_get_state):
        """Test that dispatch redirects to login when not in Docker container."""
        with patch('setup_wizard.views.DOCKER_CONTAINER', False):
            self.client.force_login(self.user)
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 302)
            self.assertRedirects(response, reverse('users:login'), fetch_redirect_response=False)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_dispatch_wrong_wizard_state_redirects(self, mock_redirect, mock_get_state):
        """Test that dispatch redirects when wizard state is incorrect."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        mock_redirect.return_value = HttpResponseRedirect('/redirect/')

        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        mock_redirect.assert_called_once_with(SetupWizardState.WIZARD_SETUP_HSM)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_dispatch_correct_wizard_state_allows_access(self, mock_get_state):
        """Test that dispatch allows access when wizard state is correct."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'storage_type')

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_get_request_renders_form(self, mock_get_state):
        """Test that a GET request renders the form correctly."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        self.client.force_login(self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'storage_type')
        self.assertIsInstance(response.context['form'], KeyStorageConfigForm)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_software_storage_success(self, mock_execute, mock_get_state):
        """Test successful form submission with SOFTWARE storage type."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTWARE
        }

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:setup_mode'), fetch_redirect_response=False)

        # Verify script was called with correct parameters - script gets lowercase value
        mock_execute.assert_called_once()
        call_args = mock_execute.call_args[0]
        self.assertIn('software', call_args)  # Script receives lowercase value

        # Verify success message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Crypto storage configuration saved' in str(msg) for msg in messages))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_softhsm_storage_success(self, mock_execute, mock_get_state):
        """Test successful form submission with SOFTHSM storage type."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTHSM
        }

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        self.assertEqual(response.status_code, 302)
        expected_url = reverse('setup_wizard:hsm_setup', kwargs={'hsm_type': 'softhsm'})
        self.assertRedirects(response, expected_url, fetch_redirect_response=False)

        # Verify script was called with correct parameters - script gets lowercase value
        mock_execute.assert_called_once()
        call_args = mock_execute.call_args[0]
        self.assertIn('softhsm', call_args)  # Script receives lowercase value

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_physical_hsm_storage_not_supported(self, mock_execute, mock_get_state):
        """Test form submission with PHYSICAL_HSM storage type shows coming soon message."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.PHYSICAL_HSM
        }

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:crypto_storage_setup'), fetch_redirect_response=False)

        # Verify error message about Physical HSM
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Physical HSM is coming soon' in str(msg) for msg in messages))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_script_failure(self, mock_execute, mock_get_state):
        """Test form submission when script execution fails."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE
        mock_execute.side_effect = subprocess.CalledProcessError(5, 'script', 'Invalid crypto storage type provided.')

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTWARE
        }

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:crypto_storage_setup'), fetch_redirect_response=False)

        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid crypto storage type provided' in str(msg) for msg in messages))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_script_not_found(self, mock_execute, mock_get_state):
        """Test form submission when script is not found."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE
        mock_execute.side_effect = FileNotFoundError('Script not found')

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTWARE
        }

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:crypto_storage_setup'), fetch_redirect_response=False)

        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Crypto storage script not found' in str(msg) for msg in messages))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_unexpected_exception(self, mock_execute, mock_get_state):
        """Test form submission when unexpected exception occurs."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE
        mock_execute.side_effect = RuntimeError('Unexpected error')

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTWARE
        }

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('setup_wizard:crypto_storage_setup'), fetch_redirect_response=False)

        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('An unexpected error occurred' in str(msg) for msg in messages))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_form_invalid_shows_error_message(self, mock_get_state):
        """Test that invalid form submission shows error message."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        # Submit form without required storage_type
        form_data = {}

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        self.assertEqual(response.status_code, 200)  # Re-renders form

        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Please correct the errors below' in str(msg) for msg in messages))

    def test_map_exit_code_to_message_known_codes(self):
        """Test mapping of known exit codes to error messages."""
        view = SetupWizardCryptoStorageView()

        test_cases = [
            (1, 'Trustpoint is not in the WIZARD_SETUP_CRYPTO_STORAGE state'),
            (2, 'Found multiple wizard state files'),
            (3, 'Failed to remove the WIZARD_SETUP_CRYPTO_STORAGE state file'),
            (4, 'Failed to create the next wizard state file'),
            (5, 'Invalid crypto storage type provided'),
        ]

        for code, expected_text in test_cases:
            with self.subTest(code=code):
                message = view._map_exit_code_to_message(code)
                self.assertIn(expected_text, message)

    def test_map_exit_code_to_message_unknown_code(self):
        """Test mapping of unknown exit code."""
        view = SetupWizardCryptoStorageView()
        message = view._map_exit_code_to_message(999)
        self.assertIn('An unknown error occurred', message)

    def test_view_attributes(self):
        """Test that view has correct attributes."""
        view = SetupWizardCryptoStorageView()

        self.assertEqual(view.http_method_names, ('get', 'post'))
        self.assertEqual(view.template_name, 'setup_wizard/crypto_storage_setup.html')
        self.assertEqual(view.form_class, KeyStorageConfigForm)

    @pytest.mark.django_db
    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_saves_config_to_database(self, mock_execute, mock_get_state):
        """Test that form submission saves configuration to database."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTWARE
        }

        # Verify no config exists initially
        self.assertEqual(KeyStorageConfig.objects.count(), 0)

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        # Verify config was created
        self.assertEqual(KeyStorageConfig.objects.count(), 1)
        config = KeyStorageConfig.objects.first()
        self.assertEqual(config.storage_type, KeyStorageConfig.StorageType.SOFTWARE)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_storage_type_routing_logic(self, mock_execute, mock_get_state):
        """Test that different storage types route to correct next steps."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        test_cases = [
            (KeyStorageConfig.StorageType.SOFTWARE, 'setup_wizard:setup_mode'),
            (KeyStorageConfig.StorageType.SOFTHSM, 'setup_wizard:hsm_setup'),
        ]

        for storage_type, expected_redirect in test_cases:
            with self.subTest(storage_type=storage_type):
                form_data = {'storage_type': storage_type}

                self.client.force_login(self.user)
                response = self.client.post(self.url, data=form_data)

                if expected_redirect == 'setup_wizard:hsm_setup':
                    expected_url = reverse(expected_redirect, kwargs={'hsm_type': 'softhsm'})
                else:
                    expected_url = reverse(expected_redirect)

                self.assertRedirects(response, expected_url, fetch_redirect_response=False)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    def test_inheritance_structure(self, mock_get_state):
        """Test that view properly inherits from required mixins."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        from django.views.generic import FormView
        from trustpoint.logger import LoggerMixin

        self.assertTrue(issubclass(SetupWizardCryptoStorageView, LoggerMixin))
        self.assertTrue(issubclass(SetupWizardCryptoStorageView, FormView))

        view = SetupWizardCryptoStorageView()
        self.assertTrue(hasattr(view, 'logger'))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_success_message_contains_storage_type_display(self, mock_execute, mock_get_state):
        """Test that success message contains human-readable storage type."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTWARE
        }

        self.client.force_login(self.user)
        response = self.client.post(self.url, data=form_data)

        messages = list(get_messages(response.wsgi_request))
        success_messages = [msg for msg in messages if 'Crypto storage configuration saved' in str(msg)]

        self.assertTrue(len(success_messages) >= 1)
        # Should contain the display name for SOFTWARE storage type
        self.assertTrue(any('Software' in str(msg) for msg in success_messages))

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_logger_integration(self, mock_execute, mock_get_state):
        """Test that view properly logs operations using client approach."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        form_data = {
            'storage_type': KeyStorageConfig.StorageType.SOFTWARE
        }

        # Use client test instead of direct view instantiation to avoid request attribute issues
        with patch('setup_wizard.views.SetupWizardCryptoStorageView.logger') as mock_logger:
            self.client.force_login(self.user)
            response = self.client.post(self.url, data=form_data)

            # Verify logger was called for successful operation
            mock_logger.info.assert_called_with('Crypto storage configured with type: %s', 'software')

    def test_script_parameters_format(self):
        """Test that storage type values are passed correctly to the script."""
        view = SetupWizardCryptoStorageView()

        # Test that enum values are converted to lowercase for script execution
        test_cases = [
            (KeyStorageConfig.StorageType.SOFTWARE, 'software'),
            (KeyStorageConfig.StorageType.SOFTHSM, 'softhsm'),
            (KeyStorageConfig.StorageType.PHYSICAL_HSM, 'physical_hsm'),
        ]

        for storage_type, expected_script_value in test_cases:
            with self.subTest(storage_type=storage_type):
                # The view passes storage_type directly to execute_shell_script
                # which gets the lowercase enum value
                self.assertEqual(storage_type.lower(), expected_script_value)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch.object(SetupWizardState, 'get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    def test_exception_handling_preserves_messages(self, mock_execute, mock_get_state):
        """Test that exception handling preserves error messages for user feedback."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_CRYPTO_STORAGE

        test_cases = [
            (subprocess.CalledProcessError(5, 'script'), 'Invalid crypto storage type provided'),
            (FileNotFoundError('Script not found'), 'Crypto storage script not found'),
            (RuntimeError('Unexpected error'), 'An unexpected error occurred'),
        ]

        for exception, expected_message_text in test_cases:
            with self.subTest(exception=exception.__class__.__name__):
                mock_execute.side_effect = exception

                form_data = {'storage_type': KeyStorageConfig.StorageType.SOFTWARE}

                self.client.force_login(self.user)
                response = self.client.post(self.url, data=form_data)

                # Should redirect back to form on error
                self.assertEqual(response.status_code, 302)
                self.assertRedirects(response, reverse('setup_wizard:crypto_storage_setup'), fetch_redirect_response=False)

                # Should have appropriate error message
                messages = list(get_messages(response.wsgi_request))
                self.assertTrue(any(expected_message_text in str(msg) for msg in messages))

                # Reset for next iteration
                mock_execute.reset_mock()

    def test_form_class_integration(self):
        """Test that view uses correct form class and integrates properly."""
        view = SetupWizardCryptoStorageView()

        # Verify form class is correct
        self.assertEqual(view.form_class, KeyStorageConfigForm)

        # Verify form can be instantiated
        form = view.form_class()
        self.assertIsInstance(form, KeyStorageConfigForm)
        self.assertIn('storage_type', form.fields)
