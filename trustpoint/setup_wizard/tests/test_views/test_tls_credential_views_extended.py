"""Comprehensive tests for TLS credential import and generate views."""

import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory
from django.db import connection

from management.forms import TlsAddFileImportPkcs12Form, TlsAddFileImportSeparateFilesForm
from management.models import KeyStorageConfig
from pki.models import CredentialModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard import SetupWizardState
from setup_wizard.forms import EmptyForm
from setup_wizard.views import (
    SetupWizardImportTlsServerCredentialPkcs12View,
    SetupWizardImportTlsServerCredentialSeparateFilesView,
    SetupWizardTlsServerCredentialApplyView,
    SetupWizardGenerateTlsServerCredentialView
)


@pytest.mark.django_db
class TestSetupWizardImportTlsServerCredentialPkcs12View:
    """Test PKCS12 TLS credential import view."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardImportTlsServerCredentialPkcs12View()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    @patch('setup_wizard.views.connection.cursor')
    def test_form_valid_success(
        self, mock_cursor, mock_get_or_create, mock_script, mock_get_state
    ):
        """Test form_valid with successful PKCS12 import."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        
        # Mock credential
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.id = 2
        mock_certificate = Mock()
        mock_certificate.id = 20
        mock_credential.certificate = mock_certificate
        
        # Mock form
        mock_form = Mock(spec=TlsAddFileImportPkcs12Form)
        mock_form.get_saved_credential.return_value = mock_credential
        
        # Mock active TLS
        mock_active_tls = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active_tls.credential_id = 1
        mock_active_tls.save = Mock()
        mock_get_or_create.return_value = (mock_active_tls, False)
        
        # Mock cursor for SQL deletion
        mock_cursor_obj = MagicMock()
        mock_cursor_obj.rowcount = 1
        mock_cursor.return_value.__enter__.return_value = mock_cursor_obj
        
        request = self.factory.post('/import-pkcs12/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        with patch('django.views.generic.FormView.form_valid') as mock_parent:
            mock_parent.return_value = Mock(status_code=302, url='/success/')
            
            response = self.view.form_valid(mock_form)
            
            assert response.status_code == 302
            mock_script.assert_called_once()
            messages_list = list(get_messages(request))
            assert any('imported successfully' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    def test_form_valid_script_error(
        self, mock_get_or_create, mock_script, mock_get_state
    ):
        """Test form_valid with script CalledProcessError."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.id = 2
        mock_certificate = Mock()
        mock_certificate.id = 20
        mock_credential.certificate = mock_certificate
        
        mock_form = Mock(spec=TlsAddFileImportPkcs12Form)
        mock_form.get_saved_credential.return_value = mock_credential
        
        mock_active_tls = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active_tls.credential_id = None
        mock_active_tls.save = Mock()
        mock_get_or_create.return_value = (mock_active_tls, True)
        
        mock_script.side_effect = subprocess.CalledProcessError(1, 'script')
        
        request = self.factory.post('/import-pkcs12/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        response = self.view.form_valid(mock_form)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('Script error' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.execute_shell_script')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    def test_form_valid_file_not_found(
        self, mock_get_or_create, mock_script, mock_get_state
    ):
        """Test form_valid with script file not found."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        
        mock_credential = Mock(spec=CredentialModel)
        mock_credential.id = 2
        mock_certificate = Mock()
        mock_certificate.id = 20
        mock_credential.certificate = mock_certificate
        
        mock_form = Mock(spec=TlsAddFileImportPkcs12Form)
        mock_form.get_saved_credential.return_value = mock_credential
        
        mock_active_tls = Mock(spec=ActiveTrustpointTlsServerCredentialModel)
        mock_active_tls.credential_id = None
        mock_active_tls.save = Mock()
        mock_get_or_create.return_value = (mock_active_tls, True)
        
        mock_script.side_effect = FileNotFoundError('Script not found')
        
        request = self.factory.post('/import-pkcs12/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        response = self.view.form_valid(mock_form)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('Transition script not found' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.get_or_create')
    def test_form_valid_unexpected_exception(
        self, mock_get_or_create, mock_get_state
    ):
        """Test form_valid with unexpected exception."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        
        mock_form = Mock(spec=TlsAddFileImportPkcs12Form)
        mock_form.get_saved_credential.side_effect = ValueError('Unexpected error')
        
        request = self.factory.post('/import-pkcs12/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        response = self.view.form_valid(mock_form)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('Error importing TLS Server Credential' in str(m) for m in messages_list)

    def test_get_error_message_from_return_code(self):
        """Test error message mapping from return codes."""
        assert 'State file missing' in self.view._get_error_message_from_return_code(1)
        assert 'Multiple state files' in self.view._get_error_message_from_return_code(2)
        assert 'Failed to remove' in self.view._get_error_message_from_return_code(3)
        assert 'Failed to create' in self.view._get_error_message_from_return_code(4)
        assert 'unknown error' in self.view._get_error_message_from_return_code(99)


@pytest.mark.django_db
class TestSetupWizardImportTlsServerCredentialSeparateFilesView:
    """Test separate files TLS credential import view."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardImportTlsServerCredentialSeparateFilesView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self):
        """Test dispatch redirects when not in Docker container."""
        request = self.factory.get('/import-separate/')
        
        response = self.view.dispatch(request)
        
        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_dispatch_wrong_state(self, mock_redirect, mock_get_state):
        """Test dispatch with wrong wizard state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_redirect.return_value = Mock(status_code=302, url='/redirect/')
        
        request = self.factory.get('/import-separate/')
        
        response = self.view.dispatch(request)
        
        assert response.status_code == 302
        mock_redirect.assert_called_once()


@pytest.mark.django_db
class TestSetupWizardTlsServerCredentialApplyView:
    """Test TLS credential application view."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardTlsServerCredentialApplyView()

    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_get_success_url_with_hsm(self, mock_get_config):
        """Test get_success_url with HSM storage type."""
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_get_config.return_value = mock_config
        
        url = self.view.get_success_url()
        
        assert 'backup-password' in url

    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_get_success_url_with_software(self, mock_get_config):
        """Test get_success_url with software storage type."""
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        mock_get_config.return_value = mock_config
        
        url = self.view.get_success_url()
        
        assert 'demo-data' in url

    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_get_success_url_config_not_found(self, mock_get_config):
        """Test get_success_url when config doesn't exist."""
        mock_get_config.side_effect = KeyStorageConfig.DoesNotExist()
        
        url = self.view.get_success_url()
        
        assert 'demo-data' in url

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_get_not_in_docker(self):
        """Test GET request when not in Docker."""
        request = self.factory.get('/apply-tls/')
        
        response = self.view.get(request)
        
        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_get_wrong_state(self, mock_redirect, mock_get_state):
        """Test GET with wrong wizard state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        mock_redirect.return_value = Mock(status_code=302, url='/redirect/')
        
        request = self.factory.get('/apply-tls/')
        
        response = self.view.get(request)
        
        assert response.status_code == 302

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_post_not_in_docker(self):
        """Test POST request when not in Docker."""
        request = self.factory.post('/apply-tls/')
        
        response = self.view.post()
        
        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.ActiveTrustpointTlsServerCredentialModel.objects.first')
    def test_form_valid_no_tls_credential(self, mock_first, mock_get_state):
        """Test form_valid when no TLS credential exists - should redirect with error."""
        mock_get_state.return_value = SetupWizardState.WIZARD_TLS_SERVER_CREDENTIAL_APPLY
        mock_first.return_value = None
        
        request = self.factory.post('/apply-tls/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib.sessions.backends.db import SessionStore
        request.session = SessionStore()
        request.session.create()
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = EmptyForm()
        
        # Exception is caught and converted to redirect with error message
        response = self.view.form_valid(form)
        assert response.status_code == 302
        
        # Check that error message was added (generic error message from outer catch)
        messages_list = list(messages_storage)
        assert len(messages_list) > 0
        assert 'An unexpected error occurred' in str(messages_list[0])


@pytest.mark.django_db
class TestSetupWizardGenerateTlsServerCredentialView:
    """Test TLS credential generation view."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardGenerateTlsServerCredentialView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self):
        """Test dispatch when not in Docker."""
        request = self.factory.get('/generate-tls/')
        
        response = self.view.dispatch(request)
        
        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_dispatch_wrong_state(self, mock_redirect, mock_get_state):
        """Test dispatch with wrong wizard state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_redirect.return_value = Mock(status_code=302, url='/redirect/')
        
        request = self.factory.get('/generate-tls/')
        
        response = self.view.dispatch(request)
        
        assert response.status_code == 302
        mock_redirect.assert_called_once()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_success(self, mock_get_state):
        """Test successful dispatch."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        
        request = self.factory.get('/generate-tls/')
        
        # Mock parent dispatch
        with patch('django.views.generic.FormView.dispatch') as mock_parent:
            mock_parent.return_value = Mock(status_code=200)
            
            response = self.view.dispatch(request)
            
            mock_parent.assert_called_once()
