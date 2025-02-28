from django.conf import settings
from django.contrib.auth.middleware import LoginRequiredMiddleware


class LoginRequired(LoginRequiredMiddleware):
    """asd"""


    def process_view(self, request, view_func, view_args, view_kwargs):  # noqa: ANN001, ANN201, D102
        if any(request.path.startswith(path) for path in settings.PUBLIC_PATHS) and not request.user.is_authenticated:
            return None

        return super().process_view(request, view_func, view_args, view_kwargs) # noqa: ANN001
