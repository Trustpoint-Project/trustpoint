"""Views for configuring PKCS#11 settings, including HSM PIN and token configuration."""

from typing import Any

from django.contrib import messages
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.generic import FormView

from management.forms import PKCS11ConfigForm


class PKCS11ConfigView(FormView[PKCS11ConfigForm]):
    """Class-based view for configuring PKCS#11 settings including HSM PIN and token configuration."""
    template_name = 'management/pkcs11.html'
    form_class = PKCS11ConfigForm
    success_url = reverse_lazy('management:pkcs11')
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context to the template."""
        context = super().get_context_data(**kwargs)
        context['page_title'] = _('PKCS#11 Configuration')
        return context

    def form_valid(self, form: PKCS11ConfigForm) -> Any:
        """Handle valid form submission."""
        success_messages = []
        error_messages = []

        try:
            form.save_token_config()
            success_messages.append(_('Token configuration saved successfully.'))
        except Exception as e:  # noqa: BLE001
            error_messages.append(_('Failed to save token configuration'))

        for msg in success_messages:
            messages.success(self.request, msg)
        for msg in error_messages:
            messages.error(self.request, msg)

        if error_messages:
            return self.form_invalid(form)

        return super().form_valid(form)

    def form_invalid(self, form: PKCS11ConfigForm) -> Any:
        """Handle invalid form submission."""
        messages.error(self.request, _('Please correct the errors below.'))
        return super().form_invalid(form)
