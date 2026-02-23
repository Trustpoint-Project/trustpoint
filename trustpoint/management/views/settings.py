"""Settings views."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from django.utils.encoding import force_str
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic.edit import FormView

from management.forms import SecurityConfigForm
from management.models import LoggingConfig, SecurityConfig
from management.security.features import AutoGenPkiFeature
from management.security.mixins import SecurityLevelMixin
from notifications.models import NotificationConfig, WeakECCCurve, WeakSignatureAlgorithm
from pki.util.keys import AutoGenPkiKeyAlgorithm
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin

if TYPE_CHECKING:
    from typing import Any

    from django.http import HttpRequest, HttpResponse


LOG_LEVELS=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
class SettingsView(PageContextMixin, SecurityLevelMixin, LoggerMixin, FormView[SecurityConfigForm]):
    """A view for managing security settings in the Trustpoint application.

    This view handles the display and processing of the SecurityConfigForm,
    allowing users to configure security-related settings such as security mode,
    auto-generated PKI, and notification configurations.
    """
    template_name = 'management/settings.html'
    form_class = SecurityConfigForm
    success_url = reverse_lazy('management:settings')

    page_category = 'management'
    page_name = 'settings'

    def get_form_kwargs(self) -> dict[str, Any]:
        """Get the keyword arguments for instantiating the form.

        This method retrieves or creates the `SecurityConfig` instance
        and includes it in the form's keyword arguments.

        Returns:
        -------
        dict
            The keyword arguments for the form, including the `instance`.
        """
        kwargs = super().get_form_kwargs()
        try:
            security_config = SecurityConfig.objects.get(id=1)
        except SecurityConfig.DoesNotExist:
            security_config = SecurityConfig.objects.create(
                notification_config=NotificationConfig.objects.create()
            )
        kwargs['instance'] = security_config
        return kwargs

    def form_valid(self, form: SecurityConfigForm) -> HttpResponse:
        """Handle valid form submission.

        This method processes the form data, applies security settings,
        and displays success messages to the user.

        Parameters
        ----------
        form : SecurityConfigForm
            The form instance containing the submitted data.

        Returns:
        -------
        HttpResponse
            A redirect response to the success URL.
        """
        old_conf = SecurityConfig.objects.get(pk=form.instance.pk) if form.instance.pk else None
        form.save()

        if 'security_mode' in form.changed_data:
            old_value = getattr(old_conf, 'security_mode', None) if old_conf else None
            new_value = form.cleaned_data.get('security_mode')

            if new_value is None:
                messages.error(self.request, 'Security mode value is missing.')
                return redirect(self.success_url)

            # Safely convert to int for comparison (default to 0 if None)
            old_int = int(old_value) if old_value is not None else 0
            new_int = int(new_value)

            if new_int > old_int:
                self.sec.reset_settings(new_value)

            form.instance.apply_security_settings()

        if 'auto_gen_pki' in form.changed_data:
            old_auto = getattr(old_conf, 'auto_gen_pki', None) if old_conf else None
            new_auto = form.cleaned_data.get('auto_gen_pki', None)
            self.logger.info(
                'auto_gen_pki changed: old=%s, new=%s',
                old_auto,
                new_auto
            )

            if old_auto != new_auto and new_auto:
                # autogen PKI got enabled
                key_alg_value = form.cleaned_data.get('auto_gen_pki_key_algorithm')
                if key_alg_value is None:
                    messages.error(self.request, 'Auto-generated PKI key algorithm is missing.')
                    return redirect(self.success_url)
                key_alg = AutoGenPkiKeyAlgorithm(key_alg_value)
                self.logger.info('Calling enable_feature for AutoGenPkiFeature with key_alg: %s', key_alg)
                self.sec.enable_feature(AutoGenPkiFeature, {'key_algorithm': key_alg})
                self.logger.info(
                    'Auto-generated PKI enabled with key algorithm: %s',
                    key_alg.name
                )

            elif old_auto != new_auto and not new_auto:
                # autogen PKI got disabled
                AutoGenPkiFeature.disable()
                self.logger.info('Auto-generated PKI disabled')

        messages.success(self.request, _('Your changes were saved successfully.'))
        return super().form_valid(form)

    def form_invalid(self, form: SecurityConfigForm) -> HttpResponse:
        """Handle invalid form submission.

        This method displays an error message and re-renders the form
        with validation errors.

        Parameters
        ----------
        form : SecurityConfigForm
            The form instance containing the submitted data.

        Returns:
        -------
        HttpResponse
            A response rendering the form with errors.
        """
        messages.error(self.request, _('Error saving the configuration'))
        return self.render_to_response(self.get_context_data(form=form))

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build the context dictionary for rendering the settings page.

        This method adds page metadata, notification configurations, log levels,
        task execution status, and the current log level to the context.

        Parameters
        ----------
        **kwargs : dict
            Additional context variables.

        Returns:
        -------
        dict[str, Any]
            The context dictionary for the template.
        """
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'management'
        context['page_name'] = 'settings'
        notification_configurations = SecurityConfig.NOTIFICATION_CONFIGURATIONS

        for settings in notification_configurations.values():
            ecc_choices = dict(WeakECCCurve.ECCCurveChoices.choices)
            signature_choices = dict(WeakSignatureAlgorithm.SignatureChoices.choices)

            settings['weak_ecc_curves'] = [
                force_str(ecc_choices.get(oid, oid)) for oid in settings.get('weak_ecc_curves', [])
            ]

            settings['weak_signature_algorithms'] = [
                force_str(signature_choices.get(oid, oid)) for oid in settings.get('weak_signature_algorithms', [])
            ]

        context['notification_configurations_json'] = json.dumps(notification_configurations)
        context['loglevels'] = LOG_LEVELS
        current_level_num = logging.getLogger().getEffectiveLevel()
        context['current_loglevel'] = logging.getLevelName(current_level_num)

        return context


class ChangeLogLevelView(View):
    """A view for changing the logging level in the Trustpoint application.

    This view handles POST requests to update the logging level dynamically.
    """
    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle POST requests to change the logging level.

        This method validates the provided log level, updates the logger
        and database configuration if valid, and redirects back to the settings page.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object containing the POST data.

        Returns:
        -------
        HttpResponse
            A redirect response to the settings page.
        """
        level = request.POST.get('loglevel', '').upper()
        if level not in LOG_LEVELS:
            messages.error(request, f'Invalid log level: {level}')
        else:
            logger = logging.getLogger()
            logger.setLevel(getattr(logging, level))
            LoggingConfig.objects.update_or_create(
                id=1,
                defaults={'log_level': level}
            )
            messages.success(request, f'Log level set to {level}')

        return redirect(reverse('management:settings'))
