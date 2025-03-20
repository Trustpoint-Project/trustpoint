"""This module contains custom middleware."""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth.middleware import LoginRequiredMiddleware  # type: ignore[attr-defined]


# TODO(AlexHx8472): Stubs not yet available in django-stubs.            # noqa: FIX002
# TODO(AlexHx8472): We may want to contribute them to the project.      # noqa: FIX002
class TrustpointLoginRequiredMiddleware(LoginRequiredMiddleware):  # type: ignore[misc]
    """Middleware that redirects all unauthenticated requests to a login page."""

    def process_view(  # type: ignore[no-untyped-def]   # noqa: ANN201
        self,
        request,  # noqa: ANN001
        view_func,  # noqa: ANN001
        view_args,  # noqa: ANN001
        view_kwargs,  # noqa: ANN001
    ):
        """Allow unauthenticated access to public paths, else redirect to login page."""
        if (not request.user.is_authenticated
            and any(request.path.startswith(path) for path in settings.PUBLIC_PATHS)):
            return None

        return super().process_view(request, view_func, view_args, view_kwargs)
