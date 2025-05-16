from typing import Any

from django.contrib import messages
from django.core.management import call_command, CommandError
from django.http import HttpResponseRedirect, HttpRequest
from django.shortcuts import redirect
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView

from home.views import SUCCESS, ERROR
from trustpoint.views.base import LoggerMixin


class ExecuteNotificationsView(LoggerMixin, TemplateView):
    """View to execute all notifications and redirect back to dashboard."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseRedirect:
        """Handles GET requests and redirects to the dashboard.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The response that redirects the user to home:dashboard.
        """
        del args
        del kwargs

        try:
            call_command('execute_all_notifications')
            messages.add_message(request, SUCCESS, _('Successfully executed notifications.'))
        except CommandError as e:
            messages.add_message(request, ERROR, _('Error executing notifications: {}').format(str(e)))

        return redirect('home:dashboard')
