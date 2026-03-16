"""Extended tests for HSM setup mixin error handling."""

import subprocess
from unittest.mock import Mock, patch

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from management.models import PKCS11Token, KeyStorageConfig
from setup_wizard.views import SetupWizardHsmSetupView


@pytest.mark.django_db
class TestHsmSetupMixinValidation:
    """Test HSM setup mixin validation methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardHsmSetupView()

    def test_validate_hsm_inputs_invalid_module_path(self):
        """Test _validate_hsm_inputs with invalid module path characters."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        # Module path with invalid characters (e.g., spaces, special chars)
        result = self.view._validate_hsm_inputs('invalid path with spaces', '0', 'label')
        
        assert result is False
        messages_list = list(get_messages(request))
        assert any('Invalid module path' in str(m) for m in messages_list)

    def test_validate_hsm_inputs_invalid_slot_non_digit(self):
        """Test _validate_hsm_inputs with non-digit slot."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        result = self.view._validate_hsm_inputs('/usr/lib/valid.so', 'abc', 'label')
        
        assert result is False
        messages_list = list(get_messages(request))
        assert any('Invalid slot value' in str(m) for m in messages_list)

    def test_validate_hsm_inputs_invalid_label(self):
        """Test _validate_hsm_inputs with invalid label characters."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        result = self.view._validate_hsm_inputs('/usr/lib/valid.so', '0', 'label with spaces')
        
        assert result is False
        messages_list = list(get_messages(request))
        assert any('Invalid label' in str(m) for m in messages_list)

    def test_validate_hsm_inputs_injection_attempt(self):
        """Test _validate_hsm_inputs detects potential command injection."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        # Try injection with semicolon - will be caught by module path validation first
        result = self.view._validate_hsm_inputs('/usr/lib/valid.so; rm -rf /', '0', 'label')
        
        assert result is False
        messages_list = list(get_messages(request))
        # Will be caught as invalid module path due to semicolon and spaces
        assert any('Invalid' in str(m) for m in messages_list)

    def test_validate_hsm_inputs_valid(self):
        """Test _validate_hsm_inputs with all valid inputs."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        result = self.view._validate_hsm_inputs('/usr/lib/libpkcs11.so', '0', 'TestLabel')
        
        assert result is True


@pytest.mark.django_db
class TestHsmSetupMixinTokenOperations:
    """Test HSM setup token creation and update operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardHsmSetupView()

    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_assign_token_to_crypto_storage_softhsm_match(self, mock_get_config):
        """Test _assign_token_to_crypto_storage with matching SoftHSM."""
        request = self.factory.post('/')
        self.view.request = request
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_config.save = Mock()
        mock_get_config.return_value = mock_config
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        
        self.view._assign_token_to_crypto_storage(mock_token, 'softhsm')
        
        assert mock_config.hsm_config == mock_token
        mock_config.save.assert_called_once_with(update_fields=['hsm_config'])

    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_assign_token_to_crypto_storage_physical_match(self, mock_get_config):
        """Test _assign_token_to_crypto_storage with matching Physical HSM."""
        request = self.factory.post('/')
        self.view.request = request
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.PHYSICAL_HSM
        mock_config.save = Mock()
        mock_get_config.return_value = mock_config
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'PhysicalToken'
        
        self.view._assign_token_to_crypto_storage(mock_token, 'physical')
        
        assert mock_config.hsm_config == mock_token
        mock_config.save.assert_called_once()

    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_assign_token_to_crypto_storage_mismatch(self, mock_get_config):
        """Test _assign_token_to_crypto_storage with mismatched types."""
        request = self.factory.post('/')
        self.view.request = request
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        mock_config.save = Mock()
        mock_get_config.return_value = mock_config
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        
        # Should log warning but not crash
        self.view._assign_token_to_crypto_storage(mock_token, 'softhsm')
        
        # Config should not be updated due to mismatch
        mock_config.save.assert_not_called()

    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_assign_token_to_crypto_storage_exception(self, mock_get_config):
        """Test _assign_token_to_crypto_storage handles exceptions."""
        request = self.factory.post('/')
        self.view.request = request
        
        mock_get_config.side_effect = RuntimeError('Config error')
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        
        # Should handle exception gracefully
        self.view._assign_token_to_crypto_storage(mock_token, 'softhsm')
        # Should not crash

    def test_generate_kek_and_dek_kek_failure(self):
        """Test _generate_kek_and_dek when KEK generation fails."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        mock_token.generate_kek.side_effect = subprocess.CalledProcessError(1, 'cmd')
        mock_token.generate_and_wrap_dek = Mock()
        
        self.view._generate_kek_and_dek(mock_token)
        
        messages_list = list(get_messages(request))
        assert any('KEK' in str(m) and 'failed' in str(m) for m in messages_list)
        # DEK generation should still be attempted
        mock_token.generate_and_wrap_dek.assert_called_once()

    def test_generate_kek_and_dek_dek_failure(self):
        """Test _generate_kek_and_dek when DEK generation fails."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        mock_token.generate_kek = Mock()
        mock_token.generate_and_wrap_dek.side_effect = RuntimeError('DEK failed')
        
        self.view._generate_kek_and_dek(mock_token)
        
        messages_list = list(get_messages(request))
        assert any('DEK' in str(m) and 'failed' in str(m) for m in messages_list)

    def test_generate_kek_and_dek_both_succeed(self):
        """Test _generate_kek_and_dek when both succeed."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        mock_token.generate_kek = Mock()
        mock_token.generate_and_wrap_dek = Mock()
        
        self.view._generate_kek_and_dek(mock_token)
        
        # No error messages should be added
        messages_list = list(get_messages(request))
        assert len([m for m in messages_list if 'failed' in str(m).lower()]) == 0


@pytest.mark.django_db
class TestHsmSetupMixinErrorHandling:
    """Test HSM setup mixin error handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardHsmSetupView()

    def test_raise_called_process_error(self):
        """Test _raise_called_process_error raises correct exception."""
        request = self.factory.post('/')
        self.view.request = request
        
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            self.view._raise_called_process_error(5)
        
        assert exc_info.value.returncode == 5

    def test_add_success_message_created(self):
        """Test _add_success_message with created token."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.get_success_context = Mock(return_value='for testing')
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        
        self.view._add_success_message('softhsm', created=True, token=mock_token)
        
        messages_list = list(get_messages(request))
        assert any('created' in str(m) and 'SOFTHSM' in str(m) for m in messages_list)

    def test_add_success_message_updated(self):
        """Test _add_success_message with updated token."""
        request = self.factory.post('/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.get_success_context = Mock(return_value='for testing')
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        
        self.view._add_success_message('physical', created=False, token=mock_token)
        
        messages_list = list(get_messages(request))
        assert any('updated' in str(m) and 'PHYSICAL' in str(m) for m in messages_list)

    def test_handle_hsm_setup_exception_called_process_error(self):
        """Test _handle_hsm_setup_exception with CalledProcessError."""
        request = self.factory.post('/', {'hsm_type': 'softhsm'})
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.get_error_redirect_url = Mock(return_value='setup_wizard:hsm_setup')
        
        exc = subprocess.CalledProcessError(2, 'cmd')
        response = self.view._handle_hsm_setup_exception(exc)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('HSM setup failed' in str(m) for m in messages_list)

    def test_handle_hsm_setup_exception_file_not_found(self):
        """Test _handle_hsm_setup_exception with FileNotFoundError."""
        request = self.factory.post('/', {'hsm_type': 'softhsm'})
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.get_error_redirect_url = Mock(return_value='setup_wizard:hsm_setup')
        
        exc = FileNotFoundError('Script not found')
        response = self.view._handle_hsm_setup_exception(exc)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('script not found' in str(m).lower() for m in messages_list)

    def test_handle_hsm_setup_exception_unexpected(self):
        """Test _handle_hsm_setup_exception with unexpected exception."""
        request = self.factory.post('/', {'hsm_type': 'physical'})
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.get_error_redirect_url = Mock(return_value='setup_wizard:hsm_setup')
        
        exc = RuntimeError('Unexpected error')
        response = self.view._handle_hsm_setup_exception(exc)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('unexpected error' in str(m).lower() for m in messages_list)

    def test_map_exit_code_to_message_all_known_codes(self):
        """Test _map_exit_code_to_message for all known exit codes."""
        known_codes = {
            1: 'Invalid number of arguments',
            2: 'not in the WIZARD_SETUP_HSM',
            3: 'multiple wizard state files',
            4: 'HSM SO PIN file not found',
            5: 'HSM PIN file not found',
            6: 'HSM SO PIN is empty',
            7: 'HSM PIN is empty',
            8: 'PKCS#11 module not found',
            9: 'Failed to initialize HSM token',
            12: 'Failed to remove',
            13: 'Failed to create',
            19: 'Failed to access HSM slot',
            20: 'Failed to create the WIZARD_AUTO_RESTORE_PASSWORD',
        }
        
        for code, expected_substr in known_codes.items():
            message = self.view._map_exit_code_to_message(code)
            assert expected_substr in message, f"Exit code {code} message should contain '{expected_substr}'"

    def test_map_exit_code_to_message_unknown_code(self):
        """Test _map_exit_code_to_message with unknown exit code."""
        message = self.view._map_exit_code_to_message(999)
        assert 'unknown error' in message.lower()
