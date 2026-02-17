"""This module contains custom middleware."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.middleware import LoginRequiredMiddleware
from django.shortcuts import redirect
from django.urls import reverse

from setup_wizard.models import SetupWizardCompletedModel

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse, HttpResponseBase


# TODO(AlexHx8472): Stubs not yet available in django-stubs.  # noqa: FIX002
# TODO(AlexHx8472): We may want to contribute them to the project.  # noqa: FIX002
class TrustpointLoginRequiredMiddleware(LoginRequiredMiddleware):
    """Middleware that redirects all unauthenticated requests to a login page."""

    def process_view(
        self,
        request: HttpRequest,
        view_func: Callable[..., Any],
        view_args: tuple[Any, ...],
        view_kwargs: dict[str, Any],
    ) -> None | HttpResponseBase:
        """Allow unauthenticated access to public paths, else redirect to login page."""
        authenticated = request.user.is_authenticated
        has_allowed_prefix = any(request.path_info.startswith(path) for path in settings.PUBLIC_PATHS)

        # TODO: setup wizard paths.

        if not authenticated and has_allowed_prefix:
            return None

        return super().process_view(request, view_func, view_args, view_kwargs)


class SetupWizardRedirectMiddleware:
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

        self.NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES = [
            '/setup-wizard'
        ]
        self.NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES_REDIRECT_PATH = reverse('home:index')

        self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_PATHS = [
            '/setup-wizard',
            '/setup-wizard/'
            '/setup-wizard/create-super-user',
            '/setup-wizard/create-super-user/',
        ]
        self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_REDIRECT_PATH = reverse('setup_wizard:index')

        self.ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_PATHS = [
            '/users/login',
            '/users/login/'
        ]
        self.ALLOWED_NON_AUTH_WIZARD_NOT_COMPLETED_REDIRECT_PATH = reverse('users:login')

        self.ALLOWED_AUTH_WIZARD_NOT_COMPLETED_PATHS = [
            '/setup-wizard/conifgure',
            '/setup-wizard/configure/',
            '/setup-wizard/summary',
            '/setup-wizard/summary/'
        ]
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
        setup_wizard_completed = SetupWizardCompletedModel.setup_wizard_completed

        if setup_wizard_completed and request.path_info.startswith(self.NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES):
            return redirect(self.NOT_ALLOWED_WIZARD_COMPLETED_PATH_PREFIXES_REDIRECT_PATH)

        users_exist = get_user_model().objects.exists()

        if not setup_wizard_completed \
                and not users_exist \
                and request.path_info not in self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_PATHS:
            return redirect(self.ALLOWED_NO_USER_EXISTS_WIZARD_NOT_COMPLETED_REDIRECT_PATH)

        authenticated = request.user.is_authenticated

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
