"""Defines views for the notifications application."""

from typing import Any

from django.contrib import messages
from django.core.management import CommandError, call_command
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import DeleteView, TemplateView

from home.views import ERROR, SUCCESS
from notifications.models import NotificationModel
from trustpoint.logger import LoggerMixin


class RefreshNotificationsView(LoggerMixin, TemplateView):
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
            messages.add_message(request, SUCCESS, _('Successfully refreshed notifications.'))
        except CommandError as e:
            messages.add_message(request, ERROR, _('Error refreshing notifications: {}').format(str(e)))

        return redirect('home:dashboard')


class NotificationDeleteView(LoggerMixin, DeleteView[NotificationModel, Any]):
    """View to delete a notification."""

    model: type[NotificationModel] = NotificationModel  # Explicitly set the model type
    template_name = 'home/notification_confirm_delete.html'
    success_url = reverse_lazy('home:dashboard')

    def delete(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Override delete method to add a success message.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Keyword arguments passed to super().delete.

        Returns:
            The HTTP response redirecting to success_url.
        """
        response = super().delete(request, *args, **kwargs)
        messages.success(request, _('Notification deleted successfully.'))
        return response




