"""Comprehensive tests for HSM setup validation and helper methods."""

import subprocess
from unittest.mock import Mock, patch

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from management.models import PKCS11Token, KeyStorageConfig
from setup_wizard.views import SetupWizardHsmSetupView


@pytest.mark.django_db
class TestHsmSetupMixinValidation:
    """Test HSM setup validation methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardHsmSetupView()
        request = self.factory.post('/hsm-setup/')
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        self.view.request = request
        self.view.setup(request)

    def test_validate_hsm_inputs_invalid_module_path(self):
        """Test validation with invalid module path."""
        result = self.view._validate_hsm_inputs('invalid path!', '0', 'token')

        assert result is False
        messages_list = list(get_messages(self.view.request))
        assert any('Invalid module path' in str(m) for m in messages_list)

    def test_validate_hsm_inputs_invalid_slot(self):
        """Test validation with invalid slot."""
        result = self.view._validate_hsm_inputs('/usr/lib/softhsm.so', 'abc', 'token')

        assert result is False
        messages_list = list(get_messages(self.view.request))
        assert any('Invalid slot value' in str(m) for m in messages_list)

    def test_validate_hsm_inputs_invalid_label(self):
        """Test validation with invalid label."""
        result = self.view._validate_hsm_inputs('/usr/lib/softhsm.so', '0', 'invalid label!')

        assert result is False
        messages_list = list(get_messages(self.view.request))
        assert any('Invalid label' in str(m) for m in messages_list)

    def test_validate_hsm_inputs_valid(self):
        """Test validation with all valid inputs."""
        result = self.view._validate_hsm_inputs('/usr/lib/softhsm.so', '0', 'test-token')

        assert result is True

    def test_run_hsm_setup_script(self):
        """Test running HSM setup script."""
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            result = self.view._run_hsm_setup_script('/usr/lib/softhsm.so', '0', 'test')

            assert result.returncode == 0
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert 'sudo' in args
            assert '/usr/lib/softhsm.so' in args
            assert '0' in args
            assert 'test' in args

    @patch('setup_wizard.views.PKCS11Token.objects.get_or_create')
    def test_get_or_update_token_new(self, mock_get_or_create):
        """Test getting or updating token (new token)."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'test'
        mock_get_or_create.return_value = (mock_token, True)

        with patch.object(self.view, '_assign_token_to_crypto_storage'):
            token, created = self.view._get_or_update_token('softhsm', '/usr/lib/softhsm.so', '0', 'test')

            assert created is True
            assert token == mock_token

    @patch('setup_wizard.views.PKCS11Token.objects.get_or_create')
    def test_get_or_update_token_existing(self, mock_get_or_create):
        """Test getting or updating token (existing token)."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'test'
        mock_token.save = Mock()
        mock_get_or_create.return_value = (mock_token, False)

        with patch.object(self.view, '_assign_token_to_crypto_storage'):
            token, created = self.view._get_or_update_token('softhsm', '/usr/lib/softhsm.so', '1', 'test')

            assert created is False
            assert token.slot == 1
            assert token.module_path == '/usr/lib/softhsm.so'
            mock_token.save.assert_called_once()

    def test_assign_token_to_crypto_storage_softhsm(self):
        """Test assigning token to crypto storage for softhsm."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'test-token'
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_config.save = Mock()

        with patch('setup_wizard.views.KeyStorageConfig.get_config', return_value=mock_config):
            self.view._assign_token_to_crypto_storage(mock_token, 'softhsm')

            assert mock_config.hsm_config == mock_token
            mock_config.save.assert_called_once()

    def test_assign_token_to_crypto_storage_physical(self):
        """Test assigning token to crypto storage for physical HSM."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'test-token'
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.PHYSICAL_HSM
        mock_config.save = Mock()

        with patch('setup_wizard.views.KeyStorageConfig.get_config', return_value=mock_config):
            self.view._assign_token_to_crypto_storage(mock_token, 'physical')

            assert mock_config.hsm_config == mock_token
            mock_config.save.assert_called_once()

    def test_generate_kek_and_dek(self):
        """Test generating KEK and DEK."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.generate_kek = Mock()
        mock_token.generate_and_wrap_dek = Mock()

        self.view._generate_kek_and_dek(mock_token)

        mock_token.generate_kek.assert_called_once()
        mock_token.generate_and_wrap_dek.assert_called_once()

    def test_add_success_message_created(self):
        """Test adding success message for created token."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'test-token'

        with patch.object(self.view, 'get_success_context', return_value='for initial setup'):
            self.view._add_success_message('softhsm', created=True, token=mock_token)

            messages_list = list(get_messages(self.view.request))
            assert any('created' in str(m).lower() for m in messages_list)

    def test_add_success_message_updated(self):
        """Test adding success message for updated token."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'test-token'

        with patch.object(self.view, 'get_success_context', return_value='for initial setup'):
            self.view._add_success_message('softhsm', created=False, token=mock_token)

            messages_list = list(get_messages(self.view.request))
            assert any('updated' in str(m).lower() for m in messages_list)

    def test_raise_called_process_error_return_code_9(self):
        """Test raising called process error with return code 9."""
        with pytest.raises(subprocess.CalledProcessError):
            self.view._raise_called_process_error(9)

    def test_raise_called_process_error_return_code_10(self):
        """Test raising called process error with return code 10."""
        with pytest.raises(subprocess.CalledProcessError):
            self.view._raise_called_process_error(10)

    def test_handle_hsm_setup_exception_called_process_error(self):
        """Test handling CalledProcessError."""
        exc = subprocess.CalledProcessError(9, 'cmd')
        self.view.request.POST = {'hsm_type': 'softhsm'}

        with patch.object(self.view, 'get_error_redirect_url', return_value='setup_wizard:hsm_setup'):
            with patch.object(self.view, '_map_exit_code_to_message', return_value='Failed to initialize HSM token'):
                response = self.view._handle_hsm_setup_exception(exc)

                assert response.status_code == 302
                messages_list = list(get_messages(self.view.request))
                assert any('HSM setup failed' in str(m) for m in messages_list)

    def test_handle_hsm_setup_exception_file_not_found(self):
        """Test handling FileNotFoundError."""
        exc = FileNotFoundError('Script not found')
        self.view.request.POST = {'hsm_type': 'softhsm'}

        with patch.object(self.view, 'get_error_redirect_url', return_value='setup_wizard:hsm_setup'):
            response = self.view._handle_hsm_setup_exception(exc)

            assert response.status_code == 302
            messages_list = list(get_messages(self.view.request))
            assert any('HSM setup script not found' in str(m) for m in messages_list)

    def test_handle_hsm_setup_exception_generic(self):
        """Test handling generic exception."""
        exc = RuntimeError('Unexpected error')
        self.view.request.POST = {'hsm_type': 'softhsm'}

        with patch.object(self.view, 'get_error_redirect_url', return_value='setup_wizard:hsm_setup'):
            response = self.view._handle_hsm_setup_exception(exc)

            assert response.status_code == 302
            messages_list = list(get_messages(self.view.request))
            assert any('unexpected error occurred' in str(m).lower() for m in messages_list)


@pytest.mark.django_db
class TestSetupWizardRestoreOptionsView:
    """Test restore options view."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        from setup_wizard.views import SetupWizardRestoreOptionsView

        self.view = SetupWizardRestoreOptionsView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self):
        """Test dispatch when not in Docker."""
        request = self.factory.get('/restore-options/')

        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_dispatch_wrong_state(self, mock_redirect, mock_get_state):
        """Test dispatch with wrong wizard state."""
        from setup_wizard import SetupWizardState

        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_redirect.return_value = Mock(status_code=302, url='/redirect/')

        request = self.factory.get('/restore-options/')

        response = self.view.dispatch(request)

        assert response.status_code == 302
        mock_redirect.assert_called_once()
