"""Tests for the middleware module."""

from unittest.mock import Mock, patch

import pytest
from django.contrib.auth.models import AnonymousUser, User
from django.http import HttpRequest, HttpResponse

from setup_wizard.models import SetupWizardCompletedModel, SetupWizardConfigModel
from trustpoint.middleware import (
    SetupWizardRedirectMiddleware,
    TrustpointLoginRequiredMiddleware,
    Workflow2InlineDrainMiddleware,
)


@pytest.fixture
def middleware():
    """Instantiate TrustpointLoginRequiredMiddleware with a mock response handler."""
    get_response = Mock(return_value=HttpResponse('ok'))
    return TrustpointLoginRequiredMiddleware(get_response=get_response)


@pytest.fixture
def workflow2_middleware():
    """Instantiate Workflow2InlineDrainMiddleware with a mock response handler."""
    get_response = Mock(return_value=Mock(status_code=200))
    return Workflow2InlineDrainMiddleware(get_response=get_response)


@pytest.fixture
def http_request():
    """Generate a basic HttpRequest."""
    request = HttpRequest()
    request.method = 'GET'
    request.user = AnonymousUser()
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


@pytest.mark.django_db
class TestTrustpointLoginRequiredMiddleware:
    """Test cases for TrustpointLoginRequiredMiddleware."""

    @pytest.fixture(autouse=True)
    def setup_public_paths(self, settings):
        settings.PUBLIC_PATHS = ['/public/', '/about/', '/api/']

    def test_unauthenticated_access_to_public_path(self, middleware, http_request):
        """Unauthenticated users should reach public paths."""
        http_request.path = '/public/resource/'
        http_request.path_info = http_request.path

        response = middleware(http_request)

        assert response.status_code == 200

    def test_unauthenticated_access_to_private_path(self, middleware, http_request):
        """Unauthenticated users should be redirected on private paths."""
        http_request.path = '/private/resource/'
        http_request.path_info = http_request.path

        response = middleware(http_request)

        assert response.status_code == 302
        assert response['Location'] == '/users/login/'

    def test_authenticated_user_access(self, middleware, http_request):
        """Authenticated users should pass through."""
        http_request.path = '/private/resource/'
        http_request.path_info = http_request.path
        http_request.user = User(username='testuser')

        response = middleware(http_request)

        assert response.status_code == 200

    def test_api_path_is_public_for_auth_handling(self, middleware, http_request):
        """API paths should bypass login redirects so DRF can handle auth."""
        http_request.path = '/api/signers/'
        http_request.path_info = http_request.path

        response = middleware(http_request)

        assert response.status_code == 200


@pytest.mark.django_db
class TestSetupWizardRedirectMiddleware:
    """Test cases for SetupWizardRedirectMiddleware."""

    @pytest.fixture
    def middleware(self):
        """Instantiate SetupWizardRedirectMiddleware with a mock response handler."""
        get_response = Mock(return_value=HttpResponse('ok'))
        return SetupWizardRedirectMiddleware(get_response=get_response)

    @staticmethod
    def _request(path: str, user):
        request = HttpRequest()
        request.method = 'GET'
        request.path = path
        request.path_info = path
        request.user = user
        request.META['SERVER_NAME'] = 'testserver'
        request.META['SERVER_PORT'] = '80'
        return request

    def test_non_docker_setup_wizard_requests_redirect_to_login(self, middleware, settings):
        """In development mode, setup-wizard paths should bounce to login."""
        settings.DOCKER_CONTAINER = False
        request = self._request('/setup-wizard/', AnonymousUser())

        response = middleware(request)

        assert response.status_code == 302
        assert response['Location'] == '/users/login/'

    def test_non_docker_non_wizard_requests_pass_through(self, middleware, settings):
        """In development mode, normal requests should pass through."""
        settings.DOCKER_CONTAINER = False
        request = self._request('/home/', AnonymousUser())

        response = middleware(request)

        assert response.status_code == 200

    def test_completed_wizard_redirects_index_to_home(self, middleware, settings):
        """Once setup is complete, the wizard index should redirect to home."""
        settings.DOCKER_CONTAINER = True
        SetupWizardCompletedModel.mark_setup_complete_once()
        request = self._request('/setup-wizard/', AnonymousUser())

        response = middleware(request)

        assert response.status_code == 302
        assert response['Location'] == '/home/'

    def test_missing_user_redirects_to_wizard_index(self, middleware, settings):
        """With no existing users, non-allowed paths should go to the wizard index."""
        settings.DOCKER_CONTAINER = True
        request = self._request('/home/', AnonymousUser())

        response = middleware(request)

        assert response.status_code == 302
        assert response['Location'] == '/setup-wizard/'

    def test_unauthenticated_user_redirects_to_login_when_user_exists(self, middleware, settings):
        """Once a user exists, unauthenticated requests should go to login."""
        settings.DOCKER_CONTAINER = True
        User.objects.create_user(username='tester', password='secret123')
        request = self._request('/home/', AnonymousUser())

        response = middleware(request)

        assert response.status_code == 302
        assert response['Location'] == '/users/login/'

    def test_authenticated_user_redirects_to_first_unsubmitted_step(self, middleware, settings):
        """Authenticated users should be sent to the first incomplete fresh-install step."""
        settings.DOCKER_CONTAINER = True
        user = User.objects.create_user(username='tester', password='secret123')
        config = SetupWizardConfigModel.get_singleton()
        config.fresh_install_crypto_storage_submitted = False
        config.fresh_install_demo_data_submitted = False
        config.fresh_install_tls_config_submitted = False
        config.fresh_install_summary_submitted = False
        config.save()
        request = self._request('/home/', user)

        response = middleware(request)

        assert response.status_code == 302
        assert response['Location'] == '/setup-wizard/fresh-install/crypto-storage/'

    def test_authenticated_user_cannot_skip_ahead(self, middleware, settings):
        """Authenticated users should be redirected back to the first incomplete step."""
        settings.DOCKER_CONTAINER = True
        user = User.objects.create_user(username='tester', password='secret123')
        config = SetupWizardConfigModel.get_singleton()
        config.fresh_install_crypto_storage_submitted = True
        config.fresh_install_demo_data_submitted = False
        config.fresh_install_tls_config_submitted = False
        config.fresh_install_summary_submitted = False
        config.save()
        request = self._request('/setup-wizard/fresh-install/summary/', user)

        response = middleware(request)

        assert response.status_code == 302
        assert response['Location'] == '/setup-wizard/fresh-install/demo-data/'


@pytest.mark.django_db
class TestWorkflow2InlineDrainMiddleware:
    """Test cases for Workflow2InlineDrainMiddleware."""

    def test_process_request_drains_backlog_opportunistically(self, workflow2_middleware, http_request):
        """The middleware should invoke the inline drain helper on each request."""
        with patch('trustpoint.middleware.WorkflowDispatchService') as mock_service:
            workflow2_middleware.process_request(http_request)

        mock_service.return_value.drain_pending_jobs_if_inline.assert_called_once_with()
