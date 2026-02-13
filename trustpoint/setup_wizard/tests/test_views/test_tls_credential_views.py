"""Tests for TLS server credential views in setup_wizard."""

from unittest.mock import Mock, patch

from django.contrib.messages import get_messages
from django.test import RequestFactory, TestCase
from django.urls import reverse

from setup_wizard import SetupWizardState
from setup_wizard.forms import EmptyForm
from setup_wizard.views import (
    SetupWizardRestoreOptionsView,
    SetupWizardSelectTlsServerCredentialView,
)


class SetupWizardSelectTlsServerCredentialViewTests(TestCase):
    """Test cases for SetupWizardSelectTlsServerCredentialView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardSelectTlsServerCredentialView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/select_tls_server_credential/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED

        request = self.factory.get('/setup_wizard/select_tls_server_credential/')
        response = self.view.dispatch(request)

        assert response.status_code == 302

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_correct_state(self, mock_get_state: Mock) -> None:
        """Test dispatch continues when in correct state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        request = self.factory.get('/setup_wizard/select_tls_server_credential/')
        self.view.request = request
        self.view.setup(request)

        response = self.view.get(request)
        assert response.status_code == 200

    def test_form_valid_generate_credential(self) -> None:
        """Test form_valid redirects to generate credential page."""
        request = self.factory.post('/setup_wizard/select_tls_server_credential/', {'generate_credential': 'true'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        form = EmptyForm()

        response = self.view.form_valid(form)

        assert response.status_code == 302
        assert 'generate-tls-server-credential' in response.url

    def test_form_valid_import_credential(self) -> None:
        """Test form_valid redirects to import credential page."""
        request = self.factory.post('/setup_wizard/select_tls_server_credential/', {'import_credential': 'true'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        form = EmptyForm()

        response = self.view.form_valid(form)

        assert response.status_code == 302
        assert 'import-tls-server-credential' in response.url

    def test_form_valid_invalid_option(self) -> None:
        """Test form_valid handles invalid option."""
        request = self.factory.post('/setup_wizard/select_tls_server_credential/', {'invalid_option': 'true'})
        from django.contrib.messages.storage.fallback import FallbackStorage

        setattr(request, 'session', 'session')
        messages_storage = FallbackStorage(request)
        setattr(request, '_messages', messages_storage)

        self.view.request = request
        form = EmptyForm()

        response = self.view.form_valid(form)

        assert response.status_code == 302


class SetupWizardRestoreOptionsViewTests(TestCase):
    """Test cases for SetupWizardRestoreOptionsView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardRestoreOptionsView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_get_not_in_docker(self) -> None:
        """Test GET redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/restore_options/')
        response = self.view.get(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_get_wrong_state(self, mock_get_state: Mock) -> None:
        """Test GET redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED

        request = self.factory.get('/setup_wizard/restore_options/')
        response = self.view.get(request)

        assert response.status_code == 302

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_get_correct_state(self, mock_get_state: Mock) -> None:
        """Test GET renders template when in correct state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE

        request = self.factory.get('/setup_wizard/restore_options/')
        self.view.request = request
        self.view.setup(request)

        response = self.view.get(request)
        assert response.status_code == 200
