"""Comprehensive tests for SetupWizardHsmSetupView dispatch and form handling."""

from unittest.mock import Mock, patch

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from management.models import KeyStorageConfig, PKCS11Token
from setup_wizard import SetupWizardState
from setup_wizard.forms import HsmSetupForm
from setup_wizard.views import SetupWizardHsmSetupView


@pytest.mark.django_db
class TestSetupWizardHsmSetupViewDispatch:
    """Test dispatch method of SetupWizardHsmSetupView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardHsmSetupView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker_container(self):
        """Test dispatch redirects when not in Docker container."""
        request = self.factory.get('/setup_wizard/hsm_setup/softhsm/')
        
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
        
        request = self.factory.get('/setup_wizard/hsm_setup/softhsm/')
        
        response = self.view.dispatch(request, hsm_type='softhsm')
        
        assert response.status_code == 302
        mock_redirect.assert_called_once_with(SetupWizardState.WIZARD_COMPLETED)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_invalid_hsm_type(self, mock_get_state):
        """Test dispatch with invalid HSM type."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        
        request = self.factory.get('/setup_wizard/hsm_setup/invalid/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='invalid')
        
        assert response.status_code == 302
        assert 'crypto-storage-setup' in response.url
        messages_list = list(get_messages(request))
        assert any('Invalid HSM type' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_dispatch_storage_type_mismatch_softhsm(self, mock_get_config, mock_get_state):
        """Test dispatch when storage type doesn't match requested HSM type (softhsm)."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTWARE
        mock_get_config.return_value = mock_config
        
        request = self.factory.get('/setup_wizard/hsm_setup/softhsm/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='softhsm')
        
        assert response.status_code == 302
        assert 'crypto-storage-setup' in response.url
        messages_list = list(get_messages(request))
        assert any('only available when' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_dispatch_storage_type_mismatch_physical(self, mock_get_config, mock_get_state):
        """Test dispatch when storage type doesn't match requested HSM type (physical)."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_get_config.return_value = mock_config
        
        request = self.factory.get('/setup_wizard/hsm_setup/physical/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='physical')
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('Physical' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    def test_dispatch_config_exception(self, mock_get_config, mock_get_state):
        """Test dispatch handles exception when getting config."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        mock_get_config.side_effect = RuntimeError('Config error')
        
        request = self.factory.get('/setup_wizard/hsm_setup/softhsm/')
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        
        response = self.view.dispatch(request, hsm_type='softhsm')
        
        assert response.status_code == 302
        assert 'crypto-storage-setup' in response.url


@pytest.mark.django_db
class TestSetupWizardHsmSetupViewFormMethods:
    """Test form-related methods of SetupWizardHsmSetupView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardHsmSetupView()

    def test_get_form_with_softhsm(self):
        """Test get_form returns form with softhsm defaults."""
        request = self.factory.get('/setup_wizard/hsm_setup/softhsm/')
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'softhsm'}
        
        form = self.view.get_form()
        
        assert isinstance(form, HsmSetupForm)
        assert form.fields['hsm_type'].initial == 'softhsm'

    def test_get_form_with_physical(self):
        """Test get_form returns form with physical HSM defaults."""
        request = self.factory.get('/setup_wizard/hsm_setup/physical/')
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'physical'}
        
        form = self.view.get_form()
        
        assert isinstance(form, HsmSetupForm)
        assert form.fields['hsm_type'].initial == 'physical'

    def test_get_form_with_custom_form_class(self):
        """Test get_form with custom form class."""
        request = self.factory.get('/setup_wizard/hsm_setup/softhsm/')
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'softhsm'}
        
        form = self.view.get_form(form_class=HsmSetupForm)
        
        assert isinstance(form, HsmSetupForm)

    def test_get_context_data(self):
        """Test get_context_data adds HSM type information."""
        request = self.factory.get('/setup_wizard/hsm_setup/softhsm/')
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'softhsm'}
        
        # Mock parent method
        with patch('django.views.generic.FormView.get_context_data', return_value={}):
            context = self.view.get_context_data()
        
        assert context['hsm_type'] == 'softhsm'
        assert context['hsm_type_display'] == 'Softhsm'

    def test_get_context_data_with_underscore(self):
        """Test get_context_data handles underscore in HSM type."""
        request = self.factory.get('/setup_wizard/hsm_setup/physical_hsm/')
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'physical_hsm'}
        
        with patch('django.views.generic.FormView.get_context_data', return_value={}):
            context = self.view.get_context_data()
        
        assert 'Physical Hsm' in context['hsm_type_display']


@pytest.mark.django_db
class TestSetupWizardHsmSetupViewHelperMethods:
    """Test helper methods of SetupWizardHsmSetupView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.view = SetupWizardHsmSetupView()

    def test_get_setup_type(self):
        """Test get_setup_type returns init_setup."""
        result = self.view.get_setup_type()
        assert result == 'init_setup'

    def test_get_success_url(self):
        """Test get_success_url returns setup_mode URL."""
        url = self.view.get_success_url()
        assert 'setup_mode' in url or 'setup-mode' in url

    def test_get_error_redirect_url(self):
        """Test get_error_redirect_url returns hsm_setup."""
        url = self.view.get_error_redirect_url()
        assert url == 'setup_wizard:hsm_setup'

    def test_get_success_context(self):
        """Test get_success_context returns initial setup context."""
        context = self.view.get_success_context()
        assert context == 'for initial setup'

    def test_get_expected_wizard_state(self):
        """Test get_expected_wizard_state returns WIZARD_SETUP_HSM."""
        state = self.view.get_expected_wizard_state()
        assert state == SetupWizardState.WIZARD_SETUP_HSM


@pytest.mark.django_db
class TestSetupWizardHsmSetupViewFormValidIntegration:
    """Test form_valid integration with various scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardHsmSetupView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    @patch('setup_wizard.views.subprocess.run')
    @patch('setup_wizard.views.PKCS11Token.objects.get_or_create')
    def test_form_valid_success_with_token_creation(
        self, mock_get_or_create, mock_run, mock_get_config, mock_get_state
    ):
        """Test form_valid with successful token creation."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_config.save = Mock()
        mock_get_config.return_value = mock_config
        
        mock_token = Mock(spec=PKCS11Token)
        mock_token.label = 'TestToken'
        mock_token.generate_kek = Mock()
        mock_token.generate_and_wrap_dek = Mock()
        mock_get_or_create.return_value = (mock_token, True)
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        request = self.factory.post('/setup_wizard/hsm_setup/softhsm/', {
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            'slot': '0',
            'label': 'TestToken',
            'hsm_type': 'softhsm'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'softhsm'}
        self.view.setup(request)
        
        form = HsmSetupForm(hsm_type='softhsm', data={
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            'slot': 0,
            'label': 'TestToken',
            'hsm_type': 'softhsm'
        })
        
        if form.is_valid():
            response = self.view.form_valid(form)
            
            assert response.status_code == 302
            messages_list = list(get_messages(request))
            assert any('created' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.KeyStorageConfig.get_config')
    @patch('setup_wizard.views.subprocess.run')
    @patch('setup_wizard.views.PKCS11Token.objects.get_or_create')
    def test_form_valid_script_failure(
        self, mock_get_or_create, mock_run, mock_get_config, mock_get_state
    ):
        """Test form_valid handles script execution failure."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_HSM
        
        mock_config = Mock(spec=KeyStorageConfig)
        mock_config.storage_type = KeyStorageConfig.StorageType.SOFTHSM
        mock_get_config.return_value = mock_config
        
        mock_result = Mock()
        mock_result.returncode = 9  # Failed to initialize HSM token
        mock_run.return_value = mock_result
        
        request = self.factory.post('/setup_wizard/hsm_setup/softhsm/', {
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            'slot': '0',
            'label': 'TestToken',
            'hsm_type': 'softhsm'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.kwargs = {'hsm_type': 'softhsm'}
        self.view.setup(request)
        
        form = HsmSetupForm(hsm_type='softhsm', data={
            'module_path': '/usr/local/lib/libpkcs11-proxy.so',
            'slot': 0,
            'label': 'TestToken',
            'hsm_type': 'softhsm'
        })
        
        if form.is_valid():
            response = self.view.form_valid(form)
            
            assert response.status_code == 302
            messages_list = list(get_messages(request))
            assert any('Failed to initialize HSM token' in str(m) for m in messages_list)
