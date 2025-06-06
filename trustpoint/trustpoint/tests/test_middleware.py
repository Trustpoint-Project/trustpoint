"""Tests for the middleware module."""

from unittest.mock import Mock

import pytest
from django.contrib.auth.models import AnonymousUser, User
from django.http import HttpRequest
from django.urls import reverse

from trustpoint.middleware import TrustpointLoginRequiredMiddleware


@pytest.fixture
def middleware():
    """Fixture to instantiate TrustpointLoginRequiredMiddleware with a mock get_response."""
    get_response = Mock()  # A mock callable to serve as the get_response argument
    return TrustpointLoginRequiredMiddleware(get_response=get_response)


@pytest.fixture
def http_request():
    """Fixture to generate a basic HttpRequest."""
    request = HttpRequest()
    request.method = 'GET'
    request.user = AnonymousUser()
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


@pytest.mark.django_db
class TestTrustpointLoginRequiredMiddleware:
    """Test cases for the TrustpointLoginRequiredMiddleware."""

    @pytest.fixture(autouse=True)
    def setup_public_paths(self, settings):
        """Set test PUBLIC_PATHS in settings."""
        settings.PUBLIC_PATHS = ['/public/', '/about/']

    def test_unauthenticated_access_to_public_path(self, middleware, http_request):
        """Ensure unauthenticated users can access public paths."""
        http_request.path = '/public/resource/'
        response = middleware.process_view(http_request, None, None, None)
        assert response is None, 'Unauthenticated users should access public paths without redirection.'

    def test_unauthenticated_access_to_private_path(self, middleware, http_request):
        """Ensure unauthenticated users accessing private paths are redirected to the login page."""
        http_request.path = '/private/resource/'
        response = middleware.process_view(http_request, None, None, None)
        assert response.status_code == 302, 'Unauthenticated users should be redirected on private paths.'
        assert response['Location'] == reverse('users:login') + '?next=/private/resource/'

    def test_authenticated_user_access(self, middleware, http_request):
        """Ensure authenticated users can access any path without redirection."""
        http_request.path = '/private/resource/'
        http_request.user = User(username='testuser')
        response = middleware.process_view(http_request, None, None, None)
        assert response is None, 'Authenticated users should access any path without redirection.'

    def test_no_public_paths_defined(self, middleware, http_request, settings):
        """Ensure middleware behaves correctly when no PUBLIC_PATHS are defined."""
        settings.PUBLIC_PATHS = []
        http_request.path = '/public/resource/'
        response = middleware.process_view(http_request, None, None, None)
        assert response.status_code == 302, 'If no public paths are defined, unauthenticated users should be redirected.'
        assert response['Location'] == reverse('users:login') + '?next=/public/resource/'
