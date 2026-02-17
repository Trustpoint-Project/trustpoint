"""Tests for the HsmSetupMixin class."""

import subprocess
from unittest.mock import Mock, patch

import pytest
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.http import HttpResponseRedirect
from django.test import RequestFactory, TestCase
from django.views.generic import FormView
from management.models import KeyStorageConfig

from setup_wizard import SetupWizardState
from setup_wizard.forms import HsmSetupForm
from setup_wizard.views import HsmSetupMixin


class ConcreteHsmSetupMixin(HsmSetupMixin, FormView[HsmSetupForm]):
    """Concrete implementation of HsmSetupMixin for testing purposes."""

    def get_setup_type(self) -> str:
        return 'test_setup'

    def get_error_redirect_url(self) -> str:
        return '/error/'

    def get_success_context(self) -> str:
        return 'for testing'

    def get_expected_wizard_state(self) -> SetupWizardState:
        return SetupWizardState.WIZARD_SETUP_HSM


class HsmSetupMixinTestCase(TestCase):
    """Test cases for HsmSetupMixin."""

    def setUp(self):
        """Set up test data."""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='testuser', password='testpassword')

        self.view = ConcreteHsmSetupMixin()
        self.request = self.factory.post('/')
        self.request.user = self.user
        self.view.request = self.request

        # Add message framework support
        from django.contrib.messages.storage.fallback import FallbackStorage

        self.request.session = {}
        self.request._messages = FallbackStorage(self.request)

    def test_validate_hsm_inputs_valid_data(self):
        """Test that valid HSM inputs pass validation."""
        result = self.view._validate_hsm_inputs('/usr/local/lib/libpkcs11-proxy.so', '0', 'Trustpoint-SoftHSM')
        self.assertTrue(result)

    def test_validate_hsm_inputs_invalid_module_path(self):
        """Test that invalid module path fails validation."""
        result = self.view._validate_hsm_inputs('invalid|path', '0', 'Trustpoint-SoftHSM')
        self.assertFalse(result)

        messages = list(get_messages(self.request))
        self.assertTrue(any('Invalid module path' in str(msg) for msg in messages))

    def test_validate_hsm_inputs_invalid_slot(self):
        """Test that invalid slot fails validation."""
        result = self.view._validate_hsm_inputs(
            '/usr/local/lib/libpkcs11-proxy.so', 'not_a_number', 'Trustpoint-SoftHSM'
        )
        self.assertFalse(result)

        messages = list(get_messages(self.request))
        self.assertTrue(any('Invalid slot value' in str(msg) for msg in messages))

    def test_validate_hsm_inputs_invalid_label(self):
        """Test that invalid label fails validation."""
        result = self.view._validate_hsm_inputs('/usr/local/lib/libpkcs11-proxy.so', '0', 'invalid-label!')
        self.assertFalse(result)

        messages = list(get_messages(self.request))
        self.assertTrue(any('Invalid label' in str(msg) for msg in messages))

    @patch('setup_wizard.views.subprocess.run')
    def test_run_hsm_setup_script_success(self, mock_subprocess):
        """Test successful HSM setup script execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        result = self.view._run_hsm_setup_script('/usr/local/lib/libpkcs11-proxy.so', '0', 'Trustpoint-SoftHSM')

        self.assertEqual(result.returncode, 0)
        mock_subprocess.assert_called_once()

        # Verify command structure
        call_args = mock_subprocess.call_args[0][0]
        self.assertIn('sudo', call_args)
        self.assertIn('/usr/local/lib/libpkcs11-proxy.so', call_args)
        self.assertIn('0', call_args)
        self.assertIn('Trustpoint-SoftHSM', call_args)
        self.assertIn('test_setup', call_args)

    @pytest.mark.django_db
    @patch('setup_wizard.views.PKCS11Token')
    def test_get_or_update_token_create_new(self, mock_token_model):
        """Test creating a new PKCS11Token."""
        mock_token = Mock()
        mock_token.label = 'Trustpoint-SoftHSM'
        mock_token.save = Mock()
        mock_token_model.objects.get_or_create.return_value = (mock_token, True)

        with patch.object(self.view, '_assign_token_to_crypto_storage') as mock_assign:
            token, created = self.view._get_or_update_token(
                'softhsm', '/usr/local/lib/libpkcs11-proxy.so', '0', 'Trustpoint-SoftHSM'
            )

        self.assertTrue(created)
        self.assertEqual(token, mock_token)
        mock_assign.assert_called_once_with(mock_token, 'softhsm')

    @pytest.mark.django_db
    @patch.object(KeyStorageConfig, 'get_config')
    def test_assign_token_to_crypto_storage_softhsm(self, mock_get_config):
        """Test assigning SoftHSM token to crypto storage."""
        mock_config = Mock()
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_config.save = Mock()
        mock_get_config.return_value = mock_config

        mock_token = Mock()
        mock_token.label = 'Trustpoint-SoftHSM'

        self.view._assign_token_to_crypto_storage(mock_token, 'softhsm')

        self.assertEqual(mock_config.hsm_config, mock_token)
        mock_config.save.assert_called_once_with(update_fields=['hsm_config'])

    def test_generate_kek_and_dek_success(self):
        """Test successful KEK and DEK generation."""
        mock_token = Mock()
        mock_token.label = 'Trustpoint-SoftHSM'
        mock_token.generate_kek = Mock()
        mock_token.generate_and_wrap_dek = Mock()

        self.view._generate_kek_and_dek(mock_token)

        mock_token.generate_kek.assert_called_once_with(key_length=256)
        mock_token.generate_and_wrap_dek.assert_called_once()

    def test_generate_kek_and_dek_kek_failure(self):
        """Test KEK generation failure with warning message."""
        mock_token = Mock()
        mock_token.label = 'Trustpoint-SoftHSM'
        mock_token.generate_kek.side_effect = RuntimeError('KEK generation failed')
        mock_token.generate_and_wrap_dek = Mock()

        # Mock the logger to avoid issues
        with patch.object(self.view, 'logger') as mock_logger:
            self.view._generate_kek_and_dek(mock_token)

        # Should still attempt DEK generation
        mock_token.generate_and_wrap_dek.assert_called_once()

    def test_raise_called_process_error(self):
        """Test raising CalledProcessError with correct parameters."""
        with self.assertRaises(subprocess.CalledProcessError) as context:
            self.view._raise_called_process_error(9)

        self.assertEqual(context.exception.returncode, 9)

    def test_add_success_message_created(self):
        """Test success message for newly created token."""
        mock_token = Mock()
        mock_token.label = 'Trustpoint-SoftHSM'

        with patch.object(self.view, 'logger'):
            self.view._add_success_message('softhsm', created=True, token=mock_token)

        messages = list(get_messages(self.request))
        self.assertEqual(len(messages), 1)
        message_text = str(messages[0])
        self.assertIn('HSM setup completed successfully', message_text)
        self.assertIn('for testing', message_text)
        self.assertIn('SOFTHSM', message_text)
        self.assertIn('created', message_text)

    def test_map_exit_code_to_message_known_codes(self):
        """Test mapping of known exit codes to error messages."""
        test_cases = [
            (1, 'Invalid number of arguments'),
            (8, 'PKCS#11 module not found'),
            (9, 'Failed to initialize HSM token'),
        ]

        for code, expected_text in test_cases:
            with self.subTest(code=code):
                message = self.view._map_exit_code_to_message(code)
                self.assertIn(expected_text, message)

    def test_map_exit_code_to_message_unknown_code(self):
        """Test mapping of unknown exit code."""
        message = self.view._map_exit_code_to_message(999)
        self.assertIn('unknown error', message)

    def test_handle_hsm_setup_exception_called_process_error(self):
        """Test handling of CalledProcessError exception."""
        exc = subprocess.CalledProcessError(9, 'script')

        with patch.object(self.view, 'logger'), patch('setup_wizard.views.redirect') as mock_redirect:
            mock_redirect.return_value = HttpResponseRedirect('/error/')
            result = self.view._handle_hsm_setup_exception(exc)
            mock_redirect.assert_called_once_with('/error/', hsm_type='softhsm', permanent=False)

        messages = list(get_messages(self.request))
        self.assertTrue(any('Failed to initialize HSM token' in str(msg) for msg in messages))

    def test_form_valid_physical_hsm_not_supported(self):
        """Test form validation with unsupported physical HSM."""
        form = Mock()
        form.cleaned_data = {
            'hsm_type': 'physical',
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            'slot': 0,
            'label': 'Physical-HSM',
        }

        with patch('setup_wizard.views.redirect') as mock_redirect:
            mock_redirect.return_value = HttpResponseRedirect('/error/')
            result = self.view.form_valid(form)
            mock_redirect.assert_called_once_with('/error/', hsm_type='physical', permanent=False)

        messages = list(get_messages(self.request))
        self.assertTrue(any('Physical HSM is not yet supported' in str(msg) for msg in messages))

    @patch('setup_wizard.views.FormView.form_valid')
    def test_form_valid_success_flow(self, mock_super_form_valid):
        """Test successful form validation flow."""
        # Setup form data
        form = Mock()
        form.cleaned_data = {
            'hsm_type': 'softhsm',
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            'slot': 0,
            'label': 'Trustpoint-SoftHSM',
        }

        mock_super_form_valid.return_value = HttpResponseRedirect('/success/')

        # Mock all the method calls in the flow
        with (
            patch.object(self.view, '_validate_hsm_inputs', return_value=True),
            patch.object(self.view, '_run_hsm_setup_script') as mock_run_script,
            patch.object(self.view, '_get_or_update_token') as mock_get_token,
            patch.object(self.view, '_generate_kek_and_dek') as mock_generate_keys,
            patch.object(self.view, '_add_success_message') as mock_add_message,
            patch.object(self.view, 'logger'),
        ):
            # Setup return values
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run_script.return_value = mock_result

            mock_token = Mock()
            mock_token.label = 'Trustpoint-SoftHSM'
            mock_get_token.return_value = (mock_token, True)

            # Call the method
            result = self.view.form_valid(form)

        # Verify the flow
        mock_run_script.assert_called_once_with('/usr/local/lib/libpkcs11-proxy.so', '0', 'Trustpoint-SoftHSM')
        mock_get_token.assert_called_once()
        mock_generate_keys.assert_called_once_with(mock_token)
        mock_add_message.assert_called_once()
        mock_super_form_valid.assert_called_once()

    def test_inheritance_structure(self):
        """Test that HsmSetupMixin properly inherits from LoggerMixin."""
        from trustpoint.logger import LoggerMixin

        self.assertTrue(issubclass(HsmSetupMixin, LoggerMixin))
        self.assertTrue(hasattr(self.view, 'logger'))

    def test_abstract_methods_implementation(self):
        """Test that abstract methods are properly implemented in test class."""
        self.assertEqual(self.view.get_setup_type(), 'test_setup')
        self.assertEqual(self.view.get_error_redirect_url(), '/error/')
        self.assertEqual(self.view.get_success_context(), 'for testing')
        self.assertEqual(self.view.get_expected_wizard_state(), SetupWizardState.WIZARD_SETUP_HSM)
