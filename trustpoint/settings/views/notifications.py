"""Views for managing notification-related settings such as expiry thresholds and weak algorithm rules."""

from typing import Any

from django.contrib import messages
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.utils.translation import gettext as _
from django.views.generic.edit import FormView
from notifications.models import NotificationConfig

from settings.forms import NotificationConfigForm


class NotificationSettingsView(FormView):
    """View for managing notification-related thresholds and security rules.

    Allows the user to configure:
    - Expiry warning thresholds for certificates and issuing CAs.
    - Minimum RSA key size.
    - Lists of weak ECC curves and signature algorithms (via ManyToMany).
    """

    template_name = 'settings/notifications.html'
    form_class = NotificationConfigForm
    success_url = reverse_lazy('settings:notifications')

    def get_form_kwargs(self) -> dict[str, Any]:
        """Return form keyword arguments, including the NotificationConfig instance.

        Ensures that the form edits the singleton NotificationConfig object.
        """
        kwargs = super().get_form_kwargs()
        config, _ = NotificationConfig.objects.get_or_create()
        kwargs['instance'] = config
        return kwargs

    def form_valid(self, form: NotificationConfigForm) -> HttpResponse:
        """Handle valid form submission.

        Saves the form and shows a success message.
        """
        form.save()
        messages.success(self.request, _('Your changes were saved successfully.'))
        return super().form_valid(form)

    def form_invalid(self, form: NotificationConfigForm) -> HttpResponse:
        """Handle invalid form submission.

        Displays an error message and re-renders the form with errors.
        """
        messages.error(self.request, _('Error saving the notification settings.'))
        return self.render_to_response(self.get_context_data(form=form))

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add custom context data for template rendering.

        Includes page identification metadata used in navigation or templates.
        """
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'settings'
        context['page_name'] = 'notification_config'
        return context
