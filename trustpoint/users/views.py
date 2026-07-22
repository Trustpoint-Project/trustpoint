"""Views for the users application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView
from django.db import DatabaseError

from setup_wizard.models import SetupWizardCompletedModel

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest, HttpResponse


class TrustpointLoginView(LoginView):
    """Login view for the trustpoint application."""

    http_method_names = ('get', 'post')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add context about initial bootstrap login if applicable."""
        context = super().get_context_data(**kwargs)

        username = getattr(settings, 'TRUSTPOINT_BOOTSTRAP_USERNAME', 'admin')
        user_model = get_user_model()

        try:
            setup_completed = SetupWizardCompletedModel.setup_wizard_completed()
            if not setup_completed:
                bootstrap_user = user_model.objects.get(username=username)
                if bootstrap_user.last_login is None:
                    context['show_bootstrap_hint'] = True
                    context['bootstrap_username'] = username
        except (user_model.DoesNotExist, DatabaseError):
            pass

        return context

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

        return super().get(request, *args, **kwargs)


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

        return super().post(request, *args, **kwargs)
