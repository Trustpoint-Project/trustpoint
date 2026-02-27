"""This module contains custom middleware."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse

from setup_wizard.models import SetupWizardCompletedModel
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse, HttpResponseBase


class TrustpointLoginRequiredMiddleware(LoggerMixin):
    """Redirect all unauthenticated requests to login, except for public paths."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware.

        Args:
            get_response: The next middleware/view callable in the Django chain.
        """
        self.get_response = get_response
        self.login_path = reverse('users:login')

    def __call__(self, request: HttpRequest) -> HttpResponseBase:
        """Handle an incoming request and apply redirects to login, if required.

        Args:
            request: The Django HTTP request.

        Returns:
            A redirect response when access is not allowed, otherwise the normal
            downstream response.
        """
        authenticated = request.user.is_authenticated
        path = request.path_info

        public = any(path.startswith(p) for p in settings.PUBLIC_PATHS)

        if not authenticated and public:
            return self.get_response(request)

        if not authenticated:
            return redirect(self.login_path)

        return self.get_response(request)


class SetupWizardRedirectMiddleware(LoggerMixin):
    """Redirect requests based on whether the global setup wizard has completed."""

    NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES: list[str]
    NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES_REDIRECT_PATH: str

    ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_PATHS: list[str]
    ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_REDIRECT_PATH: str

    ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_PATHS: list[str]
    ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH: str

    ALLOWED_AUTH_WIZARD_NOT_COMPLETED_PATHS: list[str]
    ALLOWED_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH: str

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware.

        Args:
            get_response: The next middleware/view callable in the Django chain.
        """
        self.get_response = get_response

        self.SETUP_WIZARD_PATH = '/setup-wizard'
        self.SETUP_WIZARD_REDIRECT = reverse('setup_wizard:index')
        self.NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES_REDIRECT_PATH = reverse('home:index')

        self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_PATHS = (
            '/setup-wizard',
            '/setup-wizard/',
            '/setup-wizard/create-super-user',
            '/setup-wizard/create-super-user/',
            '/setup-wizard/restore-backup/'
        )
        self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_REDIRECT_PATH = reverse('setup_wizard:index')

        self.ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_PATHS = (
            '/users/login',
            '/users/login/',
        )
        self.ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH = reverse('users:login')

        self.ALLOWED_AUTH_WIZARD_NOT_COMPLETED_PATHS = (
            '/setup-wizard/conifgure',
            '/setup-wizard/configure/',
            '/setup-wizard/summary',
            '/setup-wizard/summary/',
        )
        self.ALLOWED_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH = ''


    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Handle an incoming request and apply redirects.

        Depends on wizard status, request path and if the user is authenticated.

        Args:
            request: The Django HTTP request.

        Returns:
            A redirect response when access is not allowed, otherwise the normal
            downstream response.
        """
        self.logger.critical(f'Docker: {settings.DOCKER_CONTAINER}')
        if not settings.DOCKER_CONTAINER and request.path_info.startswith(self.SETUP_WIZARD_PATH):
            return redirect('users:login', permanent=False)

        if not settings.DOCKER_CONTAINER:
            return self.get_response(request)

        self.logger.critical('SetupWizardRedirectMiddleware')
        # setup_wizard_completed = SetupWizardCompletedModel.setup_wizard_completed
        setup_wizard_completed = False
        self.logger.critical(f'Wizard completed: {setup_wizard_completed}')

        if setup_wizard_completed is False and not request.path_info.startswith(self.SETUP_WIZARD_PATH):
            return redirect(self.SETUP_WIZARD_REDIRECT)

        if setup_wizard_completed and request.path_info.startswith(self.NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES):
            return redirect(self.NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES_REDIRECT_PATH)

        users_exist = get_user_model().objects.exists()
        self.logger.critical(f'User exists: {users_exist}')
        if not setup_wizard_completed \
                and not users_exist \
                and request.path_info not in self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_PATHS:
            self.logger.critical(f'returning: {self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_REDIRECT_PATH}')
            return redirect(self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_REDIRECT_PATH)

        authenticated = request.user.is_authenticated
        self.logger.critical(f'User authenticated: {authenticated}')

        if not setup_wizard_completed \
                and not authenticated \
                and users_exist \
                and request.path_info not in self.ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_PATHS:
            return redirect(self.ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH)

        if not setup_wizard_completed \
                and authenticated \
                and request.path_info not in self.ALLOWED_AUTH_WIZARD_NOT_COMPLETED_PATHS:
            return redirect(self.ALLOWED_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH)

        return self.get_response(request)
