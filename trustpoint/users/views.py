"""Views for the users application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.views import LoginView

from setup_wizard import SetupWizardState
from setup_wizard.views import StartupWizardRedirect
from trustpoint.settings import DOCKER_CONTAINER

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest, HttpResponse


class TrustpointLoginView(LoginView):
    """Login view for the trustpoint application."""

    http_method_names = ('get', 'post')

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Redirects to the appropriate startup wizard section if the setup wizard is not completed.

        Args:
            request: The django request object.
            *args: All positional arguments are passed to super().get().
            **kwargs: All keyword arguments are passed to super().get().

        Returns:
            The HttpResponse object, which may be a redirect.
        """
        for _ in messages.get_messages(self.request):
            pass

        if not DOCKER_CONTAINER:
            return super().get(request, *args, **kwargs)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state == SetupWizardState.WIZARD_COMPLETED:
            return super().get(request, *args, **kwargs)

        return StartupWizardRedirect.redirect_by_state(wizard_state)

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Redirects to the appropriate startup wizard section if the setup wizard is not completed.

        Args:
            request: The django request object.
            *args: All positional arguments are passed to super().post().
            **kwargs: All keyword arguments are passed to super().post().

        Returns:
            The HttpResponse object, which may be a redirect.
        """
        for _ in messages.get_messages(self.request):
            pass

        if not DOCKER_CONTAINER:
            return super().post(request, *args, **kwargs)

        wizard_state = SetupWizardState.get_current_state()
        if wizard_state == SetupWizardState.WIZARD_COMPLETED:
            return super().post(request, *args, **kwargs)

        return StartupWizardRedirect.redirect_by_state(wizard_state)
