"""Views for the users application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.views import LoginView

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
