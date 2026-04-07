"""Defines views for managing notifications."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.core.management import CommandError, call_command
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.views.generic import DeleteView, TemplateView
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView

from home.filters import NotificationFilter
from home.views import ERROR, SUCCESS
from management.models import NotificationModel, NotificationStatus
from management.models.internationalization import InternationalizationConfig
from pki.models import IssuedCredentialModel
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin
from trustpoint.settings import UIConfig
from trustpoint.views.base import SortableTableMixin

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
    from django.utils.safestring import SafeString


class NotificationsListView(
    PageContextMixin, SortableTableMixin[NotificationModel], LoggerMixin, ListView[NotificationModel]
):
    """Dedicated view for listing and filtering notifications under Management."""

    template_name = 'management/notifications/list.html'
    model = NotificationModel
    context_object_name = 'notifications'
    default_sort_param = '-created_at'
    paginate_by = UIConfig.notifications_paginate_by

    page_category = 'management'
    page_name = 'notifications'

    def get_queryset(self) -> Any:
        """Returns a queryset of NotificationModel instances."""
        all_notifications = NotificationModel.objects.all()
        notification_filter = NotificationFilter(self.request.GET, queryset=all_notifications)
        qs = notification_filter.qs

        show_unread = self.request.GET.get('unread_only', '') == '1'
        if show_unread:
            qs = qs.filter(statuses__status=NotificationStatus.StatusChoices.NEW)

        self.queryset = qs
        return super().get_queryset()

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseRedirect:
        """Handle POST actions such as 'mark all as read'.

        Args:
            request: The HTTP request object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            A redirect back to the notifications list.
        """
        del args, kwargs

        if 'mark_all_read' in request.POST:
            new_status_qs = NotificationStatus.objects.filter(
                status=NotificationStatus.StatusChoices.NEW,
            )
            if new_status_qs.exists():
                new_status = new_status_qs.first()
                if new_status is not None:
                    unread = NotificationModel.objects.filter(statuses=new_status)
                    for notification in unread:
                        notification.statuses.remove(new_status)
                    messages.success(request, _('All notifications marked as read.'))
            else:
                messages.info(request, _('No unread notifications.'))

        return redirect('management:notifications')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Fetch context data including rendered badges for each notification."""
        context = super().get_context_data(**kwargs)

        for notification in context['notifications']:
            notification.type_badge = self._render_notification_type(notification)
            notification.created = self._render_created_at(notification)

        context['unread_only'] = self.request.GET.get('unread_only', '') == '1'

        return context

    @staticmethod
    def _render_created_at(record: NotificationModel) -> SafeString:
        """Render the created_at field with a badge if the status is 'New'."""
        created_at_display = InternationalizationConfig.get_current().format_datetime(record.created_at)

        if record.statuses.filter(status=NotificationStatus.StatusChoices.NEW).exists():
            # noinspection PyDeprecation
            return format_html('{} <span class="badge bg-secondary">{}</span>', created_at_display, _('New'))

        # noinspection PyDeprecation
        return format_html('{}', created_at_display)

    @staticmethod
    def _render_notification_type(record: NotificationModel) -> SafeString:
        """Render the notification type with a badge according to the type."""
        type_display = record.get_notification_type_display()

        if record.notification_type == NotificationModel.NotificationTypes.CRITICAL:
            badge_class = 'bg-danger'
        elif record.notification_type == NotificationModel.NotificationTypes.WARNING:
            badge_class = 'bg-warning'
        elif record.notification_type == NotificationModel.NotificationTypes.INFO:
            badge_class = 'bg-info'
        else:
            badge_class = 'bg-secondary'

        # noinspection PyDeprecation
        return format_html('<span class="badge {}">{}</span>', badge_class, type_display)


class NotificationDetailsView(PageContextMixin, LoggerMixin, DetailView[NotificationModel]):
    """Renders the notification details page."""

    template_name = 'management/notifications/details.html'
    model = NotificationModel
    context_object_name = 'notification'

    page_category = 'management'
    page_name = 'notifications'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the statuses of the Notification."""
        context = super().get_context_data(**kwargs)

        # TODO(AlexHx8472): This should be generated automatically by utilizing a migration # noqa: FIX002
        new_status, _created = NotificationStatus.objects.get_or_create(status='NEW')
        solved_status, _created = NotificationStatus.objects.get_or_create(status='SOLVED')

        context['is_read'] = new_status not in self.object.statuses.all()
        context['is_solved'] = solved_status in self.object.statuses.all()
        context['notification_statuses'] = self.object.statuses.values_list('status', flat=True)

        if self.object.device is None and self.object.certificate is not None:
            issued_credential = (
                IssuedCredentialModel.objects.filter(
                    credential__certificate=self.object.certificate,
                )
                .select_related('device')
                .first()
            )
            if issued_credential is not None:
                context['associated_device'] = issued_credential.device

        return context


class NotificationMarkSolvedView(PageContextMixin, LoggerMixin, DetailView[NotificationModel]):
    """Mark notification as solved when viewed in the notification details page."""

    template_name = 'management/notifications/details.html'
    model = NotificationModel
    context_object_name = 'notification'

    page_category = 'management'
    page_name = 'notifications'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds information about the solved status of the notification."""
        context = super().get_context_data(**kwargs)

        # TODO(AlexHx8472): This should be generated automatically by utilizing a migration # noqa: FIX002
        solved_status, _ = NotificationStatus.objects.get_or_create(status='SOLVED')

        if solved_status:
            self.object.statuses.add(solved_status)

        context['is_solved'] = solved_status in self.object.statuses.all()
        return context


class NotificationToggleReadView(LoggerMixin, TemplateView):
    """Toggle the read/unread state of a notification and redirect back to its details."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseRedirect:
        """Toggle the NEW status on the notification and redirect to details."""
        del args

        pk = kwargs['pk']
        notification = NotificationModel.objects.get(pk=pk)
        new_status, _created = NotificationStatus.objects.get_or_create(status='NEW')

        if new_status in notification.statuses.all():
            notification.statuses.remove(new_status)
            messages.success(request, _('Notification marked as read.'))
        else:
            notification.statuses.add(new_status)
            messages.success(request, _('Notification marked as unread.'))

        return redirect('management:notification_details', pk=pk)


class RefreshNotificationsView(LoggerMixin, TemplateView):
    """View to execute all notifications and redirect back to notifications list."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseRedirect:
        """Handles GET requests and redirects to the notifications list."""
        del args
        del kwargs

        try:
            call_command('execute_all_notifications')
            messages.add_message(request, SUCCESS, _('Successfully refreshed notifications.'))
        except CommandError as e:
            messages.add_message(request, ERROR, _('Error refreshing notifications: {}').format(str(e)))

        return redirect('management:notifications')


class NotificationDeleteView(LoggerMixin, DeleteView[NotificationModel, Any]):
    """View to delete a notification."""

    model: type[NotificationModel] = NotificationModel  # Explicitly set the model type
    template_name = 'management/notifications/confirm_delete.html'
    success_url = reverse_lazy('management:notifications')

    page_category = 'management'
    page_name = 'notifications'

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
