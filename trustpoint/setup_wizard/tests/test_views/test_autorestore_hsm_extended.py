"""Comprehensive tests for AutoRestoreHsmSetupView."""

from unittest.mock import Mock, patch

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from management.models import KeyStorageConfig
from setup_wizard import SetupWizardState
from setup_wizard.forms import HsmSetupForm
from setup_wizard.views import AutoRestoreHsmSetupView


@pytest.mark.django_db
class TestAutoRestoreHsmSetupViewDispatch:
    """Test dispatch method of AutoRestoreHsmSetupView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = AutoRestoreHsmSetupView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self):
        """Test dispatch redirects when not in Docker container."""
        request = self.factory.get('/auto-restore/hsm-setup/softhsm/')
        
        response = self.view.dispatch(request, hsm_type='softhsm')
        
        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.StartupWizardRedirect.redirect_by_state')
    def test_dispatch_wrong_wizard_state(self, mock_redirect, mock_get_state):
        """Test dispatch redirects when wizard is in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        mock_redirect.return_value = Mock(status_code=302, url='/some-redirect/')
        
        request = self.factory.get('/auto-restore/hsm-setup/softhsm/')
        
        response = self.view.dispatch(request, hsm_type='softhsm')
        
        assert response.status_code == 302
        mock_redirect.assert_called_once()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_invalid_hsm_type(self, mock_get_state):
        """Test dispatch with invalid HSM type."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM_AUTORESTORE
        
        request = self.factory.get('/auto-restore/hsm-setup/invalid/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='invalid')
        
        assert response.status_code == 302
        assert 'login' in response.url
        messages_list = list(get_messages(request))
        assert any('Invalid HSM type' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_dispatch_storage_type_mismatch_softhsm(self, mock_get_config, mock_get_state):
        """Test dispatch when storage type doesn't match for softhsm."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM_AUTORESTORE
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.PHYSICAL_HSM
        mock_get_config.return_value = mock_config
        
        request = self.factory.get('/auto-restore/hsm-setup/softhsm/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='softhsm')
        
        assert response.status_code == 302
        assert 'login' in response.url
        messages_list = list(get_messages(request))
        assert any('only available when' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_dispatch_storage_type_mismatch_physical(self, mock_get_config, mock_get_state):
        """Test dispatch when storage type doesn't match for physical."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM_AUTORESTORE
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_get_config.return_value = mock_config
        
        request = self.factory.get('/auto-restore/hsm-setup/physical/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='physical')
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('only available when' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_dispatch_config_exception(self, mock_get_config, mock_get_state):
        """Test dispatch handles exception when getting config."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM_AUTORESTORE
        mock_get_config.side_effect = RuntimeError('Config error')
        
        request = self.factory.get('/auto-restore/hsm-setup/softhsm/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='softhsm')
        
        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_dispatch_success(self, mock_get_config, mock_get_state):
        """Test successful dispatch."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM_AUTORESTORE
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_get_config.return_value = mock_config
        
        request = self.factory.get('/auto-restore/hsm-setup/softhsm/')
        
        with patch('django.views.generic.FormView.dispatch') as mock_parent:
            mock_parent.return_value = Mock(status_code=200)
            
            response = self.view.dispatch(request, hsm_type='softhsm')
            
            mock_parent.assert_called_once()

    def test_get_form_with_softhsm(self):
        """Test get_form returns form with softhsm defaults."""
        request = self.factory.get('/auto-restore/hsm-setup/softhsm/')
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'softhsm'}
        
        form = self.view.get_form()
        
        assert isinstance(form, HsmSetupForm)
        assert form.fields['hsm_type'].initial == 'softhsm'

    def test_get_form_with_physical(self):
        """Test get_form returns form with physical HSM defaults."""
        request = self.factory.get('/auto-restore/hsm-setup/physical/')
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'physical'}
        
        form = self.view.get_form()
        
        assert isinstance(form, HsmSetupForm)
        assert form.fields['hsm_type'].initial == 'physical'

    def test_get_setup_type(self):
        """Test get_setup_type returns auto_restore_setup."""
        result = self.view.get_setup_type()
        assert result == 'auto_restore_setup'

    def test_get_expected_wizard_state(self):
        """Test get_expected_wizard_state returns WIZARD_AUTO_RESTORE."""
        state = self.view.get_expected_wizard_state()
        assert state == SetupWizardState.WIZARD_SETUP_HSM_AUTORESTORE

    def test_get_success_url(self):
        """Test get_success_url returns auto_restore_password URL."""
        url = self.view.get_success_url()
        assert 'auto_restore_password' in url or 'auto-restore-password' in url

    def test_get_error_redirect_url(self):
        """Test get_error_redirect_url returns auto_restore_hsm_setup."""
        url = self.view.get_error_redirect_url()
        assert url == 'setup_wizard:auto_restore_hsm_setup'

    def test_get_success_context(self):
        """Test get_success_context returns auto restore context."""
        context = self.view.get_success_context()
        assert context == 'for auto restore'
