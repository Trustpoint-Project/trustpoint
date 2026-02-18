"""Extended tests for backup password view error handling."""

import subprocess
from unittest.mock import Mock, patch

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory

from management.models import PKCS11Token
from setup_wizard import SetupWizardState
from setup_wizard.forms import BackupPasswordForm
from setup_wizard.views import SetupWizardBackupPasswordView


@pytest.mark.django_db
class TestSetupWizardBackupPasswordViewFormValid:
    """Test form_valid method error handling in SetupWizardBackupPasswordView."""

    def setup_method(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardBackupPasswordView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_form_valid_no_token_found(self, mock_first, mock_get_state):
        """Test form_valid when no PKCS11Token exists."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        mock_first.return_value = None
        
        request = self.factory.post('/setup_wizard/backup_password/', {
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm(data={
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        form.is_valid()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 302
        assert 'demo-data' in response.url
        messages_list = list(get_messages(request))
        assert any('No PKCS#11 token found' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_form_valid_invalid_password_type(self, mock_first, mock_get_state):
        """Test form_valid with invalid password type."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        mock_token = Mock(spec=PKCS11Token)
        mock_first.return_value = mock_token
        
        request = self.factory.post('/setup_wizard/backup_password/', {})
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm()
        form.cleaned_data = {'password': None}  # Simulate invalid password type
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 200  # form_invalid returns render
        messages_list = list(get_messages(request))
        assert any('Invalid password' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.PKCS11Token.objects.first')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_script_failed(self, mock_execute, mock_first, mock_get_state):
        """Test form_valid when shell script fails."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        mock_token = Mock(spec=PKCS11Token)
        mock_token.set_backup_password = Mock()
        mock_first.return_value = mock_token
        
        mock_execute.side_effect = subprocess.CalledProcessError(1, 'cmd')
        
        request = self.factory.post('/setup_wizard/backup_password/', {
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm(data={
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        form.is_valid()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 302
        assert 'backup-password' in response.url
        messages_list = list(get_messages(request))
        assert any('script failed' in str(m).lower() for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.PKCS11Token.objects.first')
    @patch('setup_wizard.views.execute_shell_script')
    def test_form_valid_script_not_found(self, mock_execute, mock_first, mock_get_state):
        """Test form_valid when shell script is not found."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        mock_token = Mock(spec=PKCS11Token)
        mock_token.set_backup_password = Mock()
        mock_first.return_value = mock_token
        
        mock_execute.side_effect = FileNotFoundError('Script not found')
        
        request = self.factory.post('/setup_wizard/backup_password/', {
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm(data={
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        form.is_valid()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 302
        messages_list = list(get_messages(request))
        assert any('script not found' in str(m).lower() for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_form_valid_value_error(self, mock_first, mock_get_state):
        """Test form_valid when ValueError is raised."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        mock_token = Mock(spec=PKCS11Token)
        mock_token.set_backup_password.side_effect = ValueError('Invalid input')
        mock_first.return_value = mock_token
        
        request = self.factory.post('/setup_wizard/backup_password/', {
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm(data={
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        form.is_valid()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 200  # form_invalid
        messages_list = list(get_messages(request))
        assert any('Invalid input' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_form_valid_runtime_error(self, mock_first, mock_get_state):
        """Test form_valid when RuntimeError is raised."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        mock_token = Mock(spec=PKCS11Token)
        mock_token.set_backup_password.side_effect = RuntimeError('Failed to set password')
        mock_first.return_value = mock_token
        
        request = self.factory.post('/setup_wizard/backup_password/', {
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm(data={
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        form.is_valid()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 200
        messages_list = list(get_messages(request))
        assert any('Failed to set backup password' in str(m) for m in messages_list)

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_form_valid_unexpected_exception(self, mock_first, mock_get_state):
        """Test form_valid when unexpected exception occurs."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        mock_token = Mock(spec=PKCS11Token)
        mock_token.set_backup_password.side_effect = Exception('Unexpected error')
        mock_first.return_value = mock_token
        
        request = self.factory.post('/setup_wizard/backup_password/', {
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm(data={
            'password': 'ValidPassword123!',
            'confirm_password': 'ValidPassword123!'
        })
        form.is_valid()
        
        response = self.view.form_valid(form)
        
        assert response.status_code == 200
        messages_list = list(get_messages(request))
        assert any('unexpected error' in str(m).lower() for m in messages_list)

    def test_map_exit_code_to_message_known_codes(self):
        """Test _map_exit_code_to_message with known exit codes."""
        assert 'Invalid arguments' in SetupWizardBackupPasswordView._map_exit_code_to_message(1)
        assert 'not in the WIZARD_BACKUP_PASSWORD state' in SetupWizardBackupPasswordView._map_exit_code_to_message(2)
        assert 'multiple wizard state files' in SetupWizardBackupPasswordView._map_exit_code_to_message(3)
        assert 'Failed to remove' in SetupWizardBackupPasswordView._map_exit_code_to_message(4)
        assert 'Failed to create' in SetupWizardBackupPasswordView._map_exit_code_to_message(5)

    def test_map_exit_code_to_message_unknown_code(self):
        """Test _map_exit_code_to_message with unknown exit code."""
        message = SetupWizardBackupPasswordView._map_exit_code_to_message(999)
        assert 'unknown error' in message.lower()

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_form_invalid_adds_error_message(self, mock_get_state):
        """Test form_invalid adds appropriate error message."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD
        
        request = self.factory.post('/setup_wizard/backup_password/', {})
        from django.contrib.messages.storage.fallback import FallbackStorage
        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)
        
        self.view.request = request
        self.view.setup(request)
        
        form = BackupPasswordForm(data={})
        form.is_valid()  # Will be invalid due to missing data
        
        response = self.view.form_invalid(form)
        
        messages_list = list(get_messages(request))
        assert any('correct the errors' in str(m).lower() for m in messages_list)
