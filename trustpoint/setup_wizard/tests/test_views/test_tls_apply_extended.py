"""Comprehensive tests for TLS apply view form_valid and write_pem_files methods."""

import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from management.models import KeyStorageConfig
from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard import SetupWizardState
from setup_wizard.forms import EmptyForm
from setup_wizard.views import SetupWizardTlsServerCredentialApplyView


@pytest.mark.django_db
class TestTlsServerCredentialApplyFormValid:
    """Test form_valid of TLS Server Credential Apply View."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardTlsServerCredentialApplyView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.first')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    @patch.object(SetupWizardTlsServerCredentialApplyView, '_write_pem_files')
    def test_form_valid_success_with_hsm(
        self, mock_write_pem, mock_get_config, mock_script, mock_first, mock_get_state
    ):
        """Test form_valid with successful TLS apply using HSM."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_get_config.return_value = mock_config
        
        mock_credential = Mock(spec=CredentialModel)
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_first.return_value = mock_active
        
        request = self.factory.post('/apply-tls/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = EmptyForm()
        
        with patch('django.views.generic.FormView.form_valid') as mock_parent:
            mock_parent.return_value = Mock(status_code=302, url='/success/')
            
            response = self.view.form_valid(form)
            
            assert response.status_code == 302
            mock_write_pem.assert_called_once_with(mock_credential)
            mock_script.assert_called_once()
            # Check that 'hsm' parameter was passed
            call_args = mock_script.call_args[0]
            assert 'hsm' in call_args or any('hsm' in str(arg) for arg in call_args)
            
            messages_list = list(get_messages(request))
            assert any('applied successfully' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.first')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    @patch.object(SetupWizardTlsServerCredentialApplyView, '_write_pem_files')
    def test_form_valid_success_without_hsm(
        self, mock_write_pem, mock_get_config, mock_script, mock_first, mock_get_state
    ):
        """Test form_valid with successful TLS apply without HSM."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        mock_get_config.return_value = mock_config
        
        mock_credential = Mock(spec=CredentialModel)
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_first.return_value = mock_active
        
        request = self.factory.post('/apply-tls/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = EmptyForm()
        
        with patch('django.views.generic.FormView.form_valid') as mock_parent:
            mock_parent.return_value = Mock(status_code=302, url='/success/')
            
            response = self.view.form_valid(form)
            
            assert response.status_code == 302
            # Check that 'no_hsm' parameter was passed
            call_args = mock_script.call_args[0]
            assert 'no_hsm' in call_args or any('no_hsm' in str(arg) for arg in call_args)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.first')
    @patch('setup_wizard.views.execute_shell_script')
    @patch.object(SetupWizardTlsServerCredentialApplyView, '_write_pem_files')
    def test_form_valid_config_not_found(
        self, mock_write_pem, mock_script, mock_first, mock_get_state
    ):
        """Test form_valid when KeyStorageConfig doesn't exist."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_credential = Mock(spec=CredentialModel)
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_first.return_value = mock_active
        
        request = self.factory.post('/apply-tls/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = EmptyForm()
        
        with patch('setup_wizard.views.KeyStorageConfig.get_config') as mock_get_config:
            mock_get_config.side_effect = KeyStorageConfig.DoesNotExist()
            
            with patch('django.views.generic.FormView.form_valid') as mock_parent:
                mock_parent.return_value = Mock(status_code=302, url='/success/')
                
                response = self.view.form_valid(form)
                
                assert response.status_code == 302
                # Should default to no_hsm
                call_args = mock_script.call_args[0]
                assert 'no_hsm' in call_args or any('no_hsm' in str(arg) for arg in call_args)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.first')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    @patch.object(SetupWizardTlsServerCredentialApplyView, '_write_pem_files')
    def test_form_valid_script_error(
        self, mock_write_pem, mock_get_config, mock_script, mock_first, mock_get_state
    ):
        """Test form_valid with script CalledProcessError."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        mock_get_config.return_value = mock_config
        
        mock_credential = Mock(spec=CredentialModel)
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_first.return_value = mock_active
        
        mock_script.side_effect = subprocess.CalledProcessError(1, 'script')
        
        request = self.factory.post('/apply-tls/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = EmptyForm()
        
        with patch.object(self.view, '_map_exit_code_to_message', return_value='Error msg'):
            response = self.view.form_valid(form)
            
            assert response.status_code == 302
            messages_list = list(get_messages(request))
            assert any('Error applying TLS Server Credential' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.first')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    @patch.object(SetupWizardTlsServerCredentialApplyView, '_write_pem_files')
    def test_form_valid_file_not_found(
        self, mock_write_pem, mock_get_config, mock_script, mock_first, mock_get_state
    ):
        """Test form_valid with FileNotFoundError."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        mock_get_config.return_value = mock_config
        
        mock_credential = Mock(spec=CredentialModel)
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_first.return_value = mock_active
        
        mock_script.side_effect = FileNotFoundError('Script not found')
        
        request = self.factory.post('/apply-tls/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = EmptyForm()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('File not found' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.first')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    @patch.object(SetupWizardTlsServerCredentialApplyView, '_write_pem_files')
    def test_form_valid_unexpected_exception(
        self, mock_write_pem, mock_get_config, mock_first, mock_get_state
    ):
        """Test form_valid with unexpected exception."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        mock_get_config.return_value = mock_config
        
        mock_credential = Mock(spec=CredentialModel)
        mock_active = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active.credential = mock_credential
        mock_first.return_value = mock_active
        
        mock_write_pem.side_effect = ValueError('Unexpected error')
        
        request = self.factory.post('/apply-tls/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = EmptyForm()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('unexpected error occurred' in str(m) for m in messages_list)


@pytest.mark.django_db
class TestWritePemFiles:
    """Test _write_pem_files static method."""

    @patch('setup_wizard.views.APACHE_KEY_PATH')
    @patch('setup_wizard.views.APACHE_CERT_PATH')
    @patch('setup_wizard.views.APACHE_CERT_CHAIN_PATH')
    def test_write_pem_files_success(self, mock_chain_path, mock_cert_path, mock_key_path):
        """Test successful PEM files writing."""
        # Mock serializers
        mock_private_key_serializer = Mock()
        mock_private_key_serializer.as_pkcs8_pem.return_value = b'PRIVATE KEY'
        
        mock_certificate_serializer = Mock()
        mock_certificate_serializer.as_pem.return_value = b'CERTIFICATE'
        
        mock_chain_serializer = Mock()
        mock_chain_serializer.as_pem.return_value = b'CERT CHAIN'
        
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.get_private_key_serializer.return_value = mock_private_key_serializer
        mock_credential.get_certificate_serializer.return_value = mock_certificate_serializer
        mock_credential.get_certificate_chain_serializer.return_value = mock_chain_serializer
        
        # Mock path operations
        mock_key_path.parent = Mock()
        mock_key_path.parent.mkdir = Mock()
        mock_key_path.write_text = Mock()
        mock_cert_path.write_text = Mock()
        mock_chain_path.write_text = Mock()
        
        SetupWizardTlsServerCredentialApplyView._write_pem_files(mock_credential)
        
        mock_key_path.write_text.assert_called_once_with('PRIVATE KEY')
        mock_cert_path.write_text.assert_called_once_with('CERTIFICATE')
        mock_chain_path.write_text.assert_called_once_with('CERT CHAIN')

    @patch('setup_wizard.views.APACHE_KEY_PATH')
    @patch('setup_wizard.views.APACHE_CERT_PATH')
    @patch('setup_wizard.views.APACHE_CERT_CHAIN_PATH')
    def test_write_pem_files_empty_chain(self, mock_chain_path, mock_cert_path, mock_key_path):
        """Test PEM files writing with empty certificate chain."""
        # Mock serializers
        mock_private_key_serializer = Mock()
        mock_private_key_serializer.as_pkcs8_pem.return_value = b'PRIVATE KEY'
        
        mock_certificate_serializer = Mock()
        mock_certificate_serializer.as_pem.return_value = b'CERTIFICATE'
        
        mock_chain_serializer = Mock()
        mock_chain_serializer.as_pem.return_value = b'  '  # Empty/whitespace chain
        
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.get_private_key_serializer.return_value = mock_private_key_serializer
        mock_credential.get_certificate_serializer.return_value = mock_certificate_serializer
        mock_credential.get_certificate_chain_serializer.return_value = mock_chain_serializer
        
        # Mock path operations
        mock_key_path.parent = Mock()
        mock_key_path.parent.mkdir = Mock()
        mock_key_path.write_text = Mock()
        mock_cert_path.write_text = Mock()
        mock_chain_path.exists.return_value = True
        mock_chain_path.unlink = Mock()
        
        SetupWizardTlsServerCredentialApplyView._write_pem_files(mock_credential)
        
        mock_key_path.write_text.assert_called_once()
        mock_cert_path.write_text.assert_called_once()
        mock_chain_path.unlink.assert_called_once()
        mock_chain_path.write_text.assert_not_called()
