"""Comprehensive tests for auto-restore password recovery views."""

import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, PropertyMock

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from pki.models import CaModel, CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.forms import PasswordAutoRestoreForm
from setup_wizard.views import BackupAutoRestorePasswordView


@pytest.mark.django_db
class TestBackupAutoRestorePasswordViewFormValid:
    """Test form_valid method of BackupAutoRestorePasswordView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BackupAutoRestorePasswordView()

    @patch('setup_wizard.views.execute_shell_script')
    @patch.object(BackupAutoRestorePasswordView, 'handle_backup_password_recovery')
    @patch.object(BackupAutoRestorePasswordView, '_extract_tls_certificates')
    @patch.object(BackupAutoRestorePasswordView, '_deactivate_all_issuing_cas')
    def test_form_valid_success(self, mock_deactivate, mock_extract_tls, mock_handle_recovery, mock_script):
        """Test form_valid with successful auto-restore."""
        mock_handle_recovery.return_value = True
        mock_extract_tls.return_value = None
        mock_deactivate.return_value = None
        mock_script.return_value = None

        request = self.factory.post('/auto-restore/', {'password': 'test123'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        form = PasswordAutoRestoreForm(data={'password': 'test123'})
        assert form.is_valid()
        assert form.is_valid()

        with patch('django.views.generic.FormView.form_valid') as mock_parent:
            mock_parent.return_value = Mock(status_code=302, url='/success/')

            response = self.view.form_valid(form)

            assert response.status_code == 302
            mock_handle_recovery.assert_called_once_with('test123')
            mock_extract_tls.assert_called_once()
            mock_deactivate.assert_called_once()
            mock_script.assert_called_once()

            messages_list = list(get_messages(request))
            assert any('Auto restore completed successfully' in str(m) for m in messages_list)
            assert any('Certificate Authorities have been deactivated' in str(m) for m in messages_list)

    @patch.object(BackupAutoRestorePasswordView, 'handle_backup_password_recovery')
    def test_form_valid_recovery_failure(self, mock_handle_recovery):
        """Test form_valid when recovery fails."""
        mock_handle_recovery.return_value = False

        request = self.factory.post('/auto-restore/', {'password': 'test123'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        form = PasswordAutoRestoreForm(data={'password': 'test123'})
        assert form.is_valid()

        with patch.object(self.view, 'form_invalid') as mock_form_invalid:
            mock_form_invalid.return_value = Mock(status_code=200)

            response = self.view.form_valid(form)

            mock_form_invalid.assert_called_once_with(form)

    @patch('setup_wizard.views.execute_shell_script')
    @patch.object(BackupAutoRestorePasswordView, 'handle_backup_password_recovery')
    @patch.object(BackupAutoRestorePasswordView, '_extract_tls_certificates')
    def test_form_valid_tls_extraction_failure(self, mock_extract_tls, mock_handle_recovery, mock_script):
        """Test form_valid when TLS extraction fails."""
        mock_handle_recovery.return_value = True
        mock_extract_tls.side_effect = RuntimeError('Failed to extract TLS')

        request = self.factory.post('/auto-restore/', {'password': 'test123'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        form = PasswordAutoRestoreForm(data={'password': 'test123'})
        assert form.is_valid()

        with patch.object(self.view, 'form_invalid') as mock_form_invalid:
            mock_form_invalid.return_value = Mock(status_code=200)

            response = self.view.form_valid(form)

            mock_form_invalid.assert_called_once_with(form)
            messages_list = list(get_messages(request))
            assert any('Failed to extract TLS certificates' in str(m) for m in messages_list)

    @patch('setup_wizard.views.execute_shell_script')
    @patch.object(BackupAutoRestorePasswordView, 'handle_backup_password_recovery')
    @patch.object(BackupAutoRestorePasswordView, '_extract_tls_certificates')
    def test_form_valid_script_called_process_error(self, mock_extract_tls, mock_handle_recovery, mock_script):
        """Test form_valid when shell script raises CalledProcessError."""
        mock_handle_recovery.return_value = True
        mock_extract_tls.return_value = None
        mock_script.side_effect = subprocess.CalledProcessError(1, 'script', stderr='Error')

        request = self.factory.post('/auto-restore/', {'password': 'test123'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        form = PasswordAutoRestoreForm(data={'password': 'test123'})
        assert form.is_valid()

        with patch.object(self.view, 'form_invalid') as mock_form_invalid:
            mock_form_invalid.return_value = Mock(status_code=200)
            with patch.object(self.view, '_map_exit_code_to_message') as mock_map:
                mock_map.return_value = 'Script failed'

                response = self.view.form_valid(form)

                mock_form_invalid.assert_called_once_with(form)
                messages_list = list(get_messages(request))
                assert any('Auto restore script failed' in str(m) for m in messages_list)

    @patch('setup_wizard.views.execute_shell_script')
    @patch.object(BackupAutoRestorePasswordView, 'handle_backup_password_recovery')
    @patch.object(BackupAutoRestorePasswordView, '_extract_tls_certificates')
    def test_form_valid_script_file_not_found(self, mock_extract_tls, mock_handle_recovery, mock_script):
        """Test form_valid when shell script file not found."""
        mock_handle_recovery.return_value = True
        mock_extract_tls.return_value = None
        mock_script.side_effect = FileNotFoundError('Script not found')

        request = self.factory.post('/auto-restore/', {'password': 'test123'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        form = PasswordAutoRestoreForm(data={'password': 'test123'})
        assert form.is_valid()

        with patch.object(self.view, 'form_invalid') as mock_form_invalid:
            mock_form_invalid.return_value = Mock(status_code=200)

            response = self.view.form_valid(form)

            mock_form_invalid.assert_called_once_with(form)
            messages_list = list(get_messages(request))
            assert any('Auto restore script not found' in str(m) for m in messages_list)

    @patch('setup_wizard.views.execute_shell_script')
    @patch.object(BackupAutoRestorePasswordView, 'handle_backup_password_recovery')
    @patch.object(BackupAutoRestorePasswordView, '_extract_tls_certificates')
    def test_form_valid_unexpected_exception(self, mock_extract_tls, mock_handle_recovery, mock_script):
        """Test form_valid when unexpected exception occurs."""
        mock_handle_recovery.return_value = True
        mock_extract_tls.return_value = None
        mock_script.side_effect = ValueError('Unexpected error')

        request = self.factory.post('/auto-restore/', {'password': 'test123'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        form = PasswordAutoRestoreForm(data={'password': 'test123'})
        assert form.is_valid()

        with patch.object(self.view, 'form_invalid') as mock_form_invalid:
            mock_form_invalid.return_value = Mock(status_code=200)

            response = self.view.form_valid(form)

            mock_form_invalid.assert_called_once_with(form)
            messages_list = list(get_messages(request))
            assert any('unexpected error occurred' in str(m) for m in messages_list)


@pytest.mark.django_db
class TestBackupAutoRestorePasswordViewFormInvalid:
    """Test form_invalid method of BackupAutoRestorePasswordView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BackupAutoRestorePasswordView()

    def test_form_invalid_adds_error_message(self):
        """Test form_invalid adds error message."""
        request = self.factory.post('/auto-restore/', {})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        self.view.setup(request)

        # Create invalid form (empty data, no password)
        form = PasswordAutoRestoreForm(data={})
        # Don't call is_valid() - we're testing form_invalid which receives an invalid form
        assert not form.is_valid()  # Verify it's invalid

        with patch('django.views.generic.FormView.form_invalid') as mock_parent:
            mock_parent.return_value = Mock(status_code=200)

            response = self.view.form_invalid(form)

            messages_list = list(get_messages(request))
            assert any('correct the errors below' in str(m) for m in messages_list)


@pytest.mark.django_db
class TestBackupAutoRestorePasswordViewHelpers:
    """Test helper methods of BackupAutoRestorePasswordView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.view = BackupAutoRestorePasswordView()
        self.factory = RequestFactory()
        request = self.factory.get('/test/')
        self.view.request = request

    def test_raise_runtime_error(self):
        """Test _raise_runtime_error raises with logging."""
        with pytest.raises(RuntimeError, match='Test error message'):
            self.view._raise_runtime_error('Test error message')

    @patch('setup_wizard.views.CaModel.objects.filter')
    def test_deactivate_all_issuing_cas_with_active_cas(self, mock_filter):
        """Test _deactivate_all_issuing_cas with active CAs."""
        mock_queryset = Mock()
        mock_queryset.count.return_value = 3
        mock_queryset.update.return_value = 3
        mock_filter.return_value = mock_queryset

        self.view._deactivate_all_issuing_cas()

        mock_filter.assert_called_once_with(is_active=True)
        mock_queryset.update.assert_called_once_with(is_active=False)

    @patch('setup_wizard.views.CaModel.objects.filter')
    def test_deactivate_all_issuing_cas_no_active_cas(self, mock_filter):
        """Test _deactivate_all_issuing_cas with no active CAs."""
        mock_queryset = Mock()
        mock_queryset.count.return_value = 0
        mock_filter.return_value = mock_queryset

        self.view._deactivate_all_issuing_cas()

        mock_filter.assert_called_once_with(is_active=True)
        mock_queryset.update.assert_not_called()

    @patch('setup_wizard.views.CaModel.objects.filter')
    def test_deactivate_all_issuing_cas_exception(self, mock_filter):
        """Test _deactivate_all_issuing_cas handles exception."""
        mock_filter.side_effect = Exception('Database error')

        # Should not raise exception
        self.view._deactivate_all_issuing_cas()

    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    @patch('setup_wizard.views.NGINX_KEY_PATH')
    @patch('setup_wizard.views.NGINX_CERT_PATH')
    @patch('setup_wizard.views.NGINX_CERT_CHAIN_PATH')
    def test_extract_tls_certificates_success(self, mock_chain_path, mock_cert_path, mock_key_path, mock_get):
        """Test _extract_tls_certificates with successful extraction."""
        # Mock credential and serializers
        mock_private_key_serializer = Mock()
        mock_private_key_serializer.as_pkcs8_pem.return_value = b'PRIVATE KEY PEM'

        mock_certificate_serializer = Mock()
        mock_certificate_serializer.as_pem.return_value = b'CERTIFICATE PEM'

        mock_chain_serializer = Mock()
        mock_chain_serializer.as_pem.return_value = b'CHAIN PEM'

        mock_credential = Mock(spec=CredentialModel)
        mock_credential.get_private_key_serializer.return_value = mock_private_key_serializer
        mock_credential.get_certificate_serializer.return_value = mock_certificate_serializer
        mock_credential.get_certificate_chain_serializer.return_value = mock_chain_serializer

        mock_active_tls = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active_tls.credential = mock_credential
        mock_get.return_value = mock_active_tls

        # Mock path operations
        mock_key_path.parent = Mock()
        mock_key_path.parent.mkdir = Mock()
        mock_key_path.write_text = Mock()
        mock_cert_path.write_text = Mock()
        mock_chain_path.write_text = Mock()

        self.view._extract_tls_certificates()

        mock_get.assert_called_once_with(id=1)
        mock_key_path.write_text.assert_called_once_with('PRIVATE KEY PEM')
        mock_cert_path.write_text.assert_called_once_with('CERTIFICATE PEM')
        mock_chain_path.write_text.assert_called_once_with('CHAIN PEM')

    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_extract_tls_certificates_not_found(self, mock_get):
        """Test _extract_tls_certificates when credential not found."""
        mock_get.side_effect = ActiveTrustpointTlsServerCredentialModel.DoesNotExist()

        with pytest.raises(RuntimeError, match='Active TLS credential not found'):
            self.view._extract_tls_certificates()

    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_extract_tls_certificates_no_credential(self, mock_get):
        """Test _extract_tls_certificates when active TLS has no credential."""
        mock_active_tls = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active_tls.credential = None
        mock_get.return_value = mock_active_tls

        with pytest.raises(RuntimeError, match='TLS credential not found in database'):
            self.view._extract_tls_certificates()

    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    @patch('setup_wizard.views.NGINX_KEY_PATH')
    @patch('setup_wizard.views.NGINX_CERT_PATH')
    @patch('setup_wizard.views.NGINX_CERT_CHAIN_PATH')
    def test_extract_tls_certificates_empty_chain(self, mock_chain_path, mock_cert_path, mock_key_path, mock_get):
        """Test _extract_tls_certificates with empty trust store."""
        # Mock credential with empty chain
        mock_private_key_serializer = Mock()
        mock_private_key_serializer.as_pkcs8_pem.return_value = b'PRIVATE KEY PEM'

        mock_certificate_serializer = Mock()
        mock_certificate_serializer.as_pem.return_value = b'CERTIFICATE PEM'

        mock_chain_serializer = Mock()
        mock_chain_serializer.as_pem.return_value = b'  '  # Empty/whitespace

        mock_credential = Mock(spec=CredentialModel)
        mock_credential.get_private_key_serializer.return_value = mock_private_key_serializer
        mock_credential.get_certificate_serializer.return_value = mock_certificate_serializer
        mock_credential.get_certificate_chain_serializer.return_value = mock_chain_serializer

        mock_active_tls = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active_tls.credential = mock_credential
        mock_get.return_value = mock_active_tls

        # Mock path operations
        mock_key_path.parent = Mock()
        mock_key_path.parent.mkdir = Mock()
        mock_key_path.write_text = Mock()
        mock_cert_path.write_text = Mock()
        mock_chain_path.exists.return_value = True
        mock_chain_path.unlink = Mock()

        self.view._extract_tls_certificates()

        mock_chain_path.unlink.assert_called_once()
        mock_chain_path.write_text.assert_not_called()

    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get')
    def test_extract_tls_certificates_general_exception(self, mock_get):
        """Test _extract_tls_certificates with general exception."""
        mock_get.side_effect = Exception('Unexpected error')

        with pytest.raises(RuntimeError, match='Failed to extract TLS certificates'):
            self.view._extract_tls_certificates()
