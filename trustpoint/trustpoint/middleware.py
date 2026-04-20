"""This module contains custom middleware."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

from setup_wizard.models import SetupWizardCompletedModel, SetupWizardConfigModel
from trustpoint.logger import LoggerMixin
from workflows2.services.dispatch import WorkflowDispatchService

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse, HttpResponseBase


logger = logging.getLogger(__name__)


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

        if not authenticated and not request.path_info.startswith(self.login_path):
            return redirect(self.login_path)

        return self.get_response(request)


class SetupWizardRedirectMiddleware(LoggerMixin):
    """Redirect requests based on whether the global setup wizard has completed."""

    USERS_LOGIN_REVERSE = reverse('users:login')

    SETUP_WIZARD_PATH = '/setup-wizard'
    SETUP_WIZARD_INDEX_REVERSE = reverse('setup_wizard:index')

    WIZARD_COMPLETED_HOME_REVERSE = reverse('home:index')

    ALLOWED_NO_USER_CREATED = (
        '/setup-wizard',
        '/setup-wizard/',
        '/setup-wizard/create-super-user',
        '/setup-wizard/create-super-user/',
        '/setup-wizard/restore-backup',
        '/setup-wizard/restore-backup/',
    )

    ALLOWED_NON_AUTH_PATHS = (
        '/users/login',
        '/users/login/',
    )
    ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH = reverse('users:login')

    ALLOWED_AUTH_WIZARD_NOT_COMPLETED_PATHS = (
        '/setup-wizard/fresh-install',
        '/users/logout',
    )

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware.

        Args:
            get_response: The next middleware/view callable in the Django chain.
        """
        self.get_response = get_response

    @classmethod
    def _get_fresh_install_step_paths(cls) -> tuple[tuple[str, str, bool], ...]:
        """Return fresh-install step path metadata in wizard order."""
        config_model = SetupWizardConfigModel.get_singleton()
        return (
            (
                '/setup-wizard/fresh-install/crypto-storage/',
                reverse('setup_wizard:fresh_install_crypto_storage'),
                config_model.fresh_install_crypto_storage_submitted,
            ),
            (
                '/setup-wizard/fresh-install/demo-data/',
                reverse('setup_wizard:fresh_install_demo_data'),
                config_model.fresh_install_demo_data_submitted,
            ),
            (
                '/setup-wizard/fresh-install/tls-config/',
                reverse('setup_wizard:fresh_install_tls_config'),
                config_model.fresh_install_tls_config_submitted,
            ),
            (
                '/setup-wizard/fresh-install/summary/',
                reverse('setup_wizard:fresh_install_summary'),
                config_model.fresh_install_summary_submitted,
            ),
        )

    @classmethod
    def _get_first_unsubmitted_redirect_path(cls) -> str:
        """Return the first fresh-install step that has not yet been submitted."""
        step_paths = cls._get_fresh_install_step_paths()
        first_unsubmitted = next(
            (redirect_path for _path_prefix, redirect_path, submitted in step_paths if not submitted),
            None,
        )
        if first_unsubmitted is not None:
            return first_unsubmitted
        return step_paths[-1][1]

    @classmethod
    def _get_fresh_install_redirect_path(cls, path: str) -> str | None:
        """Return the required fresh-install step redirect for a blocked path."""
        if not path.startswith('/setup-wizard/fresh-install'):
            return None

        if path in {'/setup-wizard/fresh-install/cancel', '/setup-wizard/fresh-install/cancel/'}:
            return None

        step_paths = cls._get_fresh_install_step_paths()
        first_unsubmitted_index = next(
            (index for index, (_path_prefix, _redirect_path, submitted) in enumerate(step_paths) if not submitted),
            len(step_paths) - 1,
        )

        requested_step_index = next(
            (
                index
                for index, (path_prefix, _redirect_path, _submitted) in enumerate(step_paths)
                if path.startswith(path_prefix)
            ),
            None,
        )
        if requested_step_index is None:
            return step_paths[first_unsubmitted_index][1]

        if requested_step_index <= first_unsubmitted_index:
            return None

        return step_paths[first_unsubmitted_index][1]

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Handle an incoming request and apply redirects.

        Depends on wizard status, request path and if the user is authenticated.

        Args:
            request: The Django HTTP request.

        Returns:
            A redirect response when access is not allowed, otherwise the normal
            downstream response.
        """
        redirect_dest: str | None = None

        msg = f'\n\npath_info: {request.path_info}'
        self.logger.critical(msg)

        # handle dev environment
        if not settings.DOCKER_CONTAINER:
            if request.path_info.startswith(self.SETUP_WIZARD_PATH):
                return redirect(self.USERS_LOGIN_REVERSE, permanent=False)
            return self.get_response(request)

        setup_wizard_completed = SetupWizardCompletedModel.setup_wizard_completed()
        msg = f'setup_wizard_completed: {setup_wizard_completed}'
        self.logger.critical(msg)

        # handle wizard completed cases
        if setup_wizard_completed:
            if request.path_info.startswith(self.SETUP_WIZARD_INDEX_REVERSE):
                return redirect(self.WIZARD_COMPLETED_HOME_REVERSE, permanent=False)
            return self.get_response(request)

        users_exists = get_user_model().objects.exists()
        msg = f'user_exists: {users_exists}'
        self.logger.critical(msg)

        # if no user exists, only allow the views before creating a user
        if not users_exists and request.path_info not in self.ALLOWED_NO_USER_CREATED:
            self.logger.critical('redirecting to wizard index')
            redirect_dest = self.SETUP_WIZARD_INDEX_REVERSE

        authenticated = request.user.is_authenticated
        msg = f'authenticated: {authenticated}'
        self.logger.critical(msg)

        # if a user exists but is not authenticated, redirect to login page
        if not authenticated and users_exists and request.path_info not in self.ALLOWED_NON_AUTH_PATHS:
            redirect_dest = self.USERS_LOGIN_REVERSE

        # if user is authenticated (wizard not completed), only allow views to finish up the wizard
        if (
            authenticated
            and users_exists
            and not request.path_info.startswith(self.ALLOWED_AUTH_WIZARD_NOT_COMPLETED_PATHS)
        ):
            redirect_dest = self._get_first_unsubmitted_redirect_path()

        if authenticated and users_exists and redirect_dest is None:
            redirect_dest = self._get_fresh_install_redirect_path(request.path_info)

        if redirect_dest:
            self.logger.critical('redirecting dest: %s', redirect_dest)
            return redirect(redirect_dest, permanent=False)

        self.logger.critical('NOT redirecting')
        return self.get_response(request)


class Workflow2InlineDrainMiddleware(MiddlewareMixin):
    """Let the web process drain queued workflow jobs when inline execution is active."""

    def process_request(self, request: HttpRequest) -> None:
        """Drain backlog opportunistically before handling the current request."""
        del request
        try:
            WorkflowDispatchService().drain_pending_jobs_if_inline()
        except Exception:
            logger.exception('Failed to drain queued Workflow jobs inline.')
