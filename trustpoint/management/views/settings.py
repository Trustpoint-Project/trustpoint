"""Settings views with dedicated views for each setting type."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.core.management import call_command
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils import translation
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic import TemplateView
from django.views.generic.edit import FormView

from management.forms import (
    InternationalizationConfigForm,
    LoggingConfigForm,
    NotificationConfigForm,
    SecurityConfigForm,
)
from management.models import InternationalizationConfig, LoggingConfig, NotificationConfig, SecurityConfig
from management.security.features import AutoGenPkiFeature
from management.security.mixins import SecurityLevelMixin
from pki.util.keys import AutoGenPkiKeyAlgorithm
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


class SettingsFormViewMixin[FormType: (
    InternationalizationConfigForm | LoggingConfigForm | NotificationConfigForm | SecurityConfigForm
)](
    PageContextMixin,
    SecurityLevelMixin,
    LoggerMixin,
    FormView[FormType],
):
    """Base mixin for all settings form views."""

    page_category = 'management'
    page_name = 'settings'

    setting_type: str = 'general'

    def get_success_url(self) -> str:
        """Return the URL to redirect to after successful form submission."""
        return f"{reverse_lazy('management:settings')}?tab={self.setting_type}"

    def form_valid(self, form: FormType) -> HttpResponse:
        """Handle valid form submission."""
        form.save()
        messages.success(self.request, _('Your changes were saved successfully.'))
        return super().form_valid(form)

    def form_invalid(self, form: FormType) -> HttpResponse:
        """Handle invalid form submission."""
        messages.error(self.request, _('Error saving the configuration'))
        return super().form_invalid(form)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build the context dictionary for rendering the page."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = self.page_category
        context['page_name'] = self.page_name
        context['setting_type'] = self.setting_type
        return context


class SettingsTabView(TemplateView):
    """Main settings view with tab interface."""

    template_name = 'management/settings.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build the context for the settings page."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'management'
        context['page_name'] = 'settings'

        context['active_tab'] = self.request.GET.get('tab', 'language')

        internationalization_view = InternationalizationSettingsView()
        internationalization_view.request = self.request
        internationalization_view.setup(self.request)
        context['internationalization_form'] = internationalization_view.get_form()

        security_view = SecuritySettingsView()
        security_view.request = self.request
        security_view.setup(self.request)
        context['security_form'] = security_view.get_form()
        context['notification_configurations_json'] = SecurityConfig.get_settings_preview_json()

        logging_view = LoggingSettingsView()
        logging_view.request = self.request
        logging_view.setup(self.request)
        context['logging_form'] = logging_view.get_form()
        context['loglevels'] = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        current_level_num = logging.getLogger().getEffectiveLevel()
        context['current_loglevel'] = logging.getLevelName(current_level_num)

        notification_view = NotificationSettingsView()
        notification_view.request = self.request
        notification_view.setup(self.request)
        context['notification_form'] = notification_view.get_form()
        context['notification_config'] = NotificationConfig.get()

        return context





class InternationalizationSettingsView(SettingsFormViewMixin[InternationalizationConfigForm]):
    """View for managing internationalization settings."""

    template_name = 'management/includes/internationalization_configuration.html'
    form_class = InternationalizationConfigForm
    setting_type = 'internationalization'

    def get_initial(self) -> dict[str, Any]:
        """Get initial form data with current internationalization settings."""
        initial = super().get_initial()

        config, _ = InternationalizationConfig.objects.get_or_create(
            id=1,
            defaults={
                'date_format': InternationalizationConfig.DateFormatChoices.YYYY_MM_DD_24_SEC,
                'language': translation.get_language() or InternationalizationConfig.LanguageChoices.EN,
                'timezone': 'UTC',
            },
        )

        initial['date_format'] = config.date_format
        initial['language'] = config.language
        initial['timezone'] = config.timezone
        return initial

    def form_valid(self, form: InternationalizationConfigForm) -> HttpResponse:
        """Handle valid internationalization form submission."""
        date_format = form.cleaned_data['date_format']
        language = form.cleaned_data['language']
        timezone = form.cleaned_data['timezone']

        self.logger.info(
            'Changing internationalization settings to: date_format=%s, language=%s, timezone=%s',
            date_format,
            language,
            timezone,
        )

        InternationalizationConfig.objects.update_or_create(
            id=1,
            defaults={
                'date_format': date_format,
                'language': language,
                'timezone': timezone,
            },
        )

        translation.activate(language)

        response = redirect(self.get_success_url())
        response.set_cookie(
            key='django_language',
            value=language,
            max_age=365 * 24 * 60 * 60,
            path='/',
            samesite='Lax',
        )

        messages.success(self.request,_('Internationalization configuration saved successfully.'))
        return response


class SecuritySettingsView(SettingsFormViewMixin[SecurityConfigForm]):
    """View for managing security settings."""

    template_name = 'management/includes/security_configuration.html'
    form_class = SecurityConfigForm
    setting_type = 'security'
    success_url = reverse_lazy('management:settings-security')

    def get_form_kwargs(self) -> dict[str, Any]:
        """Get the keyword arguments for instantiating the form.

        Returns:
            The keyword arguments for the form, including the instance.
        """
        kwargs = super().get_form_kwargs()
        try:
            security_config = SecurityConfig.objects.get(id=1)
        except SecurityConfig.DoesNotExist:
            security_config = SecurityConfig.objects.create()
        kwargs['instance'] = security_config
        return kwargs

    def form_valid(self, form: SecurityConfigForm) -> HttpResponse:
        """Handle valid security form submission.

        This method processes the form data, applies security settings,
        and displays success messages to the user.

        Parameters:
            form: The form instance containing the submitted data.

        Returns:
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
        return redirect(self.get_success_url())

    def form_invalid(self, form: SecurityConfigForm) -> HttpResponse:
        """Handle invalid security form submission."""
        messages.error(self.request, _('Error saving the configuration'))
        extra: dict[str, Any] = {'form': form}
        if hasattr(form, '_violations'):
            extra['policy_violations'] = form._violations  # noqa: SLF001
            extra['policy_violations_mode_label'] = form._violations_mode_label  # noqa: SLF001
            form.errors.pop('__all__', None)
        return self.render_to_response(self.get_context_data(**extra))

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build the context dictionary for the security settings page."""
        context = super().get_context_data(**kwargs)
        context['notification_configurations_json'] = SecurityConfig.get_settings_preview_json()
        return context


class LoggingSettingsView(SettingsFormViewMixin[LoggingConfigForm]):
    """View for managing logging settings."""

    template_name = 'management/includes/log_configuration.html'
    form_class = LoggingConfigForm
    setting_type = 'log'

    def get_initial(self) -> dict[str, Any]:
        """Get initial form data with current log level."""
        initial = super().get_initial()
        current_level_num = logging.getLogger().getEffectiveLevel()
        initial['loglevel'] = logging.getLevelName(current_level_num)
        return initial

    def form_valid(self, form: LoggingConfigForm) -> HttpResponse:
        """Handle valid logging form submission."""
        level = form.cleaned_data['loglevel']
        self.logger.info('Changing log level to: %s', level)

        logger = logging.getLogger()
        logger.setLevel(getattr(logging, level))

        LoggingConfig.objects.update_or_create(
            id=1,
            defaults={'log_level': level}
        )

        self.logger.info('Log level successfully changed to: %s', level)
        messages.success(self.request, _('Log level changed to %(level)s') % {'level': level})
        return redirect(self.get_success_url())

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build the context dictionary for the logging settings page."""
        context = super().get_context_data(**kwargs)
        context['loglevels'] = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        current_level_num = logging.getLogger().getEffectiveLevel()
        context['current_loglevel'] = logging.getLevelName(current_level_num)
        return context


class NotificationSettingsView(SettingsFormViewMixin[NotificationConfigForm]):
    """View for managing notification settings."""

    template_name = 'management/includes/notification_configuration.html'
    form_class = NotificationConfigForm
    setting_type = 'notifications'

    def get_form_kwargs(self) -> dict[str, Any]:
        """Get the keyword arguments for instantiating the form."""
        kwargs = super().get_form_kwargs()
        notification_config = NotificationConfig.get()
        kwargs['instance'] = notification_config
        return kwargs

    def form_valid(self, form: NotificationConfigForm) -> HttpResponse:
        """Handle valid notification form submission."""
        notification_config = form.instance
        was_enabled = notification_config.enabled

        form.save()
        notification_config.refresh_from_db()
        cleaned_enabled = notification_config.enabled

        if cleaned_enabled:
            needs_init = not notification_config.notification_cycle_enabled or not was_enabled

            if needs_init:
                try:
                    notification_config.notification_cycle_enabled = True
                    notification_config.save(update_fields=['notification_cycle_enabled'])

                    call_command('init_notifications')

                    if not was_enabled:
                        messages.success(
                            self.request,
                            _('Notifications enabled and notification cycle initialized.')
                        )
                    else:
                        messages.success(
                            self.request,
                            _('Notification configuration saved and cycle reinitialized.')
                        )
                except Exception:
                    self.logger.exception('Error initializing notifications')
                    messages.error(
                        self.request,
                        _('Notifications saved but error initializing notification cycle.')
                    )
            else:
                messages.success(self.request, _('Notification configuration saved successfully.'))
        else:
            if notification_config.notification_cycle_enabled:
                notification_config.notification_cycle_enabled = False
                notification_config.save(update_fields=['notification_cycle_enabled'])
            messages.success(self.request, _('Notifications disabled successfully.'))

        return redirect(self.get_success_url())

    def form_invalid(self, form: NotificationConfigForm) -> HttpResponse:
        """Handle invalid notification form submission."""
        self.logger.error('Notification form errors: %s', form.errors)
        self.logger.error('Notification form non-field errors: %s', form.non_field_errors())
        messages.error(self.request, _('Error saving notification configuration'))
        return super().form_invalid(form)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build the context dictionary for the notification settings page."""
        context = super().get_context_data(**kwargs)
        notification_config = NotificationConfig.get()
        context['notification_form'] = context.get('form', self.get_form())
        context['notification_config'] = notification_config
        return context


class ChangeLogLevelView(View):
    """Deprecated view for changing the logging level."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle POST requests to change the logging level."""
        form = LoggingConfigForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, _('Log level updated successfully.'))
        else:
            messages.error(request, _('Invalid log level.'))

        return redirect(reverse_lazy('management:settings') + '?tab=log')
