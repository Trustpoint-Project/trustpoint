"""This module contains custom middleware."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth.middleware import LoginRequiredMiddleware

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponseBase


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
        if not request.user.is_authenticated and any(request.path.startswith(path) for path in settings.PUBLIC_PATHS):
            return None

        return super().process_view(request, view_func, view_args, view_kwargs)
