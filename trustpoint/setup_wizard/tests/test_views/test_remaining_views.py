"""Tests for TLS import, demo data, and super user views."""

from unittest.mock import Mock, patch

from django.test import RequestFactory, TestCase

from setup_wizard import SetupWizardState
from setup_wizard.views import (
    SetupWizardCreateSuperUserView,
    SetupWizardDemoDataView,
    SetupWizardGenerateTlsServerCredentialView,
    SetupWizardImportTlsServerCredentialMethodSelectView,
    SetupWizardImportTlsServerCredentialPkcs12View,
    SetupWizardImportTlsServerCredentialSeparateFilesView,
    SetupWizardTlsServerCredentialApplyCancelView,
    SetupWizardTlsServerCredentialApplyView,
)


class SetupWizardGenerateTlsServerCredentialViewTests(TestCase):
    """Test cases for SetupWizardGenerateTlsServerCredentialView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardGenerateTlsServerCredentialView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/generate_tls/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/generate_tls/')
        response = self.view.dispatch(request)

        assert response.status_code == 302


class SetupWizardImportTlsServerCredentialMethodSelectViewTests(TestCase):
    """Test cases for SetupWizardImportTlsServerCredentialMethodSelectView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardImportTlsServerCredentialMethodSelectView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/import_method_select/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/import_method_select/')
        response = self.view.dispatch(request)

        assert response.status_code == 302

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_get_correct_state(self, mock_get_state: Mock) -> None:
        """Test GET renders template when in correct state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_SETUP_MODE
        
        request = self.factory.get('/setup_wizard/import_method_select/')
        self.view.request = request
        self.view.setup(request)
        
        response = self.view.get(request)
        assert response.status_code == 200


class SetupWizardImportTlsServerCredentialPkcs12ViewTests(TestCase):
    """Test cases for SetupWizardImportTlsServerCredentialPkcs12View."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardImportTlsServerCredentialPkcs12View()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/import_pkcs12/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/import_pkcs12/')
        response = self.view.dispatch(request)

        assert response.status_code == 302


class SetupWizardImportTlsServerCredentialSeparateFilesViewTests(TestCase):
    """Test cases for SetupWizardImportTlsServerCredentialSeparateFilesView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardImportTlsServerCredentialSeparateFilesView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/import_separate/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/import_separate/')
        response = self.view.dispatch(request)

        assert response.status_code == 302


class SetupWizardTlsServerCredentialApplyViewTests(TestCase):
    """Test cases for SetupWizardTlsServerCredentialApplyView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardTlsServerCredentialApplyView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/tls_apply/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/tls_apply/')
        response = self.view.dispatch(request)

        assert response.status_code == 302


class SetupWizardTlsServerCredentialApplyCancelViewTests(TestCase):
    """Test cases for SetupWizardTlsServerCredentialApplyCancelView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardTlsServerCredentialApplyCancelView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_get_not_in_docker(self) -> None:
        """Test GET redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/tls_cancel/')
        response = self.view.get(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_get_wrong_state(self, mock_get_state: Mock) -> None:
        """Test GET redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/tls_cancel/')
        response = self.view.get(request)

        assert response.status_code == 302


class SetupWizardDemoDataViewTests(TestCase):
    """Test cases for SetupWizardDemoDataView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardDemoDataView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/demo_data/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/demo_data/')
        response = self.view.dispatch(request)

        assert response.status_code == 302


class SetupWizardCreateSuperUserViewTests(TestCase):
    """Test cases for SetupWizardCreateSuperUserView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = SetupWizardCreateSuperUserView()

    @patch('setup_wizard.views.DOCKER_CONTAINER', False)
    def test_dispatch_not_in_docker(self) -> None:
        """Test dispatch redirects to login when not in Docker."""
        request = self.factory.get('/setup_wizard/create_super_user/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
        assert 'login' in response.url

    @patch('setup_wizard.views.DOCKER_CONTAINER', True)
    @patch('setup_wizard.views.SetupWizardState.get_current_state')
    def test_dispatch_wrong_state(self, mock_get_state: Mock) -> None:
        """Test dispatch redirects when in wrong state."""
        mock_get_state.return_value = SetupWizardState.WIZARD_COMPLETED
        
        request = self.factory.get('/setup_wizard/create_super_user/')
        response = self.view.dispatch(request)

        assert response.status_code == 302
