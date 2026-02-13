"""Tests for backup password views in setup_wizard."""

from unittest.mock import Mock, patch

from django.contrib.messages import get_messages
from django.test import RequestFactory, TestCase
from django.urls import reverse

from management.models import PKCS11Token
from setup_wizard import SetupWizardState
from setup_wizard.forms import BackupPasswordForm, PasswordAutoRestoreForm
from setup_wizard.views import (
    BackupAutoRestorePasswordView,
    BackupPasswordRecoveryMixin,
    BackupRestoreView,
    SetupWizardBackupPasswordView,
)


class SetupWizardBackupPasswordViewTests(TestCase):
    """Test cases for SetupWizardBackupPasswordView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardBackupPasswordView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/backup_password/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED

        request = self.factory.get('/setup_wizard/backup_password/')
        response = self.view.dispatch(request)

        assert response.status_code == 302

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_get_context_data(self, mock_get_state: Mock) -> None:
        """Test get_context_data adds password requirements."""
        mock_get_state.return_value = SetupWizardState.WIZARD_BACKUP_PASSWORD

        request = self.factory.get('/setup_wizard/backup_password/')
        self.view.request = request
        self.view.setup(request)

        context = self.view.get_context_data()

        assert 'password_requirements' in context
        assert len(context['password_requirements']) == 4


class BackupPasswordRecoveryMixinTests(TestCase):
    """Test cases for BackupPasswordRecoveryMixin."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.mixin = BackupPasswordRecoveryMixin()

    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_get_token_for_recovery_no_token(self, mock_first: Mock) -> None:
        """Test _get_token_for_recovery when no token exists."""
        mock_first.return_value = None

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._get_token_for_recovery()
        assert result is None

    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_get_token_for_recovery_no_backup(self, mock_first: Mock) -> None:
        """Test _get_token_for_recovery when token has no backup encryption."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.has_backup_encryption.return_value = False
        mock_first.return_value = mock_token

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._get_token_for_recovery()
        assert result is None

    @patch('setup_wizard.views.PKCS11Token.objects.first')
    def test_get_token_for_recovery_success(self, mock_first: Mock) -> None:
        """Test _get_token_for_recovery success."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.has_backup_encryption.return_value = True
        mock_first.return_value = mock_token

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._get_token_for_recovery()
        assert result == mock_token

    def test_ensure_kek_exists_already_present(self) -> None:
        """Test _ensure_kek_exists when KEK already exists."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.kek = 'existing_kek'

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._ensure_kek_exists(mock_token)
        assert result is True

    def test_ensure_kek_exists_generate_new(self) -> None:
        """Test _ensure_kek_exists generates new KEK."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.kek = None
        mock_token.generate_kek = Mock()

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._ensure_kek_exists(mock_token)
        assert result is False
        mock_token.generate_kek.assert_called_once_with(key_length=256)

    def test_recover_dek_with_password_success(self) -> None:
        """Test _recover_dek_with_password success."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.get_dek_with_backup_password.return_value = b'recovered_dek'

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._recover_dek_with_password(mock_token, 'password123')
        assert result == b'recovered_dek'

    def test_recover_dek_with_password_invalid(self) -> None:
        """Test _recover_dek_with_password with invalid password."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.get_dek_with_backup_password.side_effect = ValueError('Invalid password')

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._recover_dek_with_password(mock_token, 'wrong_password')
        assert result is None

    def test_wrap_and_save_dek_success(self) -> None:
        """Test _wrap_and_save_dek success."""
        mock_token = Mock(spec=PKCS11Token)
        mock_token.wrap_dek.return_value = b'wrapped_dek'
        mock_token.save = Mock()

        request = self.factory.get('/')
        request._messages = Mock()
        self.mixin.request = request

        result = self.mixin._wrap_and_save_dek(mock_token, b'dek_bytes', had_kek=True)
        assert result is True
        mock_token.save.assert_called_once()


class BackupRestoreViewTests(TestCase):
    """Test cases for BackupRestoreView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BackupRestoreView()

    def test_view_only_allows_post(self) -> None:
        """Test that only POST is allowed."""
        request = self.factory.get('/setup_wizard/restore/')
        response = self.view.dispatch(request)

        assert response.status_code == 405  # Method Not Allowed

    @patch('setup_wizard.views.settings')
    @patch('setup_wizard.views.call_command')
    def test_post_invalid_form(self, mock_call_command: Mock, mock_settings: Mock) -> None:
        """Test POST with invalid form."""
        request = self.factory.post('/setup_wizard/restore/', {})
        request._messages = Mock()

        self.view.request = request
        response = self.view.post(request)

        assert response.status_code == 302
        assert 'login' in response.url


class BackupAutoRestorePasswordViewTests(TestCase):
    """Test cases for BackupAutoRestorePasswordView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BackupAutoRestorePasswordView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/auto_restore_password/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED

        request = self.factory.get('/setup_wizard/auto_restore_password/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
