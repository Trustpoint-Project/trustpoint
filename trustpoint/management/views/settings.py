"""Settings views with dedicated views for each setting type."""

from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.core.management import call_command
from django.db import connection
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils import timezone, translation
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django.views import View
from django.views.generic import TemplateView
from django.views.generic.edit import FormView

from management.forms import (
    InternationalizationConfigForm,
    LoggingConfigForm,
    NotificationConfigForm,
    SecurityConfigForm,
    WorkflowExecutionConfigForm,
)
from management.models import InternationalizationConfig, LoggingConfig, NotificationConfig, SecurityConfig
from management.models.audit_log import AuditLog
from management.models.workflows2 import WorkflowExecutionConfig
from management.security.features import AutoGenPkiFeature
from management.security.mixins import SecurityLevelMixin
from pki.util.keys import AutoGenPkiKeyAlgorithm
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import PageContextMixin
from workflows2.models import Workflow2WorkerHeartbeat

if TYPE_CHECKING:
    from datetime import datetime

    from django.http import HttpRequest, HttpResponse

APP_STARTED_AT = timezone.now()
BYTE_UNIT = 1024
MIN_PARTS_COUNT = 2


def format_uptime(started_at: datetime) -> str:
    """Return a human-readable uptime string."""
    delta = timezone.now() - started_at
    total_seconds = int(delta.total_seconds())

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    if days > 0:
        return f'{days}d {hours}h {minutes}m {seconds}s'
    if hours > 0:
        return f'{hours}h {minutes}m {seconds}s'
    return f'{minutes}m {seconds}s'


def format_bytes(size: int) -> str:
    """Convert bytes into a human-readable string."""
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    value = float(size)

    for unit in units:
        if value < BYTE_UNIT or unit == units[-1]:
            if unit == 'B':
                return f'{int(value)} {unit}'
            return f'{value:.2f} {unit}'
        value /= BYTE_UNIT

    return f'{size} B'


def get_database_size() -> str:
    """Return the size of the current database."""
    if connection.vendor != 'postgresql':
        return 'Unavailable'

    with connection.cursor() as cursor:
        cursor.execute('SELECT pg_database_size(current_database())')
        row = cursor.fetchone()

    size_bytes = row[0] if row else 0
    return format_bytes(size_bytes)


def read_int_file(path: str) -> int:
    """Read an integer value from a file."""
    return int(Path(path).read_text(encoding='utf-8').strip())


def read_text_file(path: str) -> str:
    """Read a text value from a file."""
    return Path(path).read_text(encoding='utf-8').strip()


def get_memory_metrics() -> dict[str, str | bool]:
    """Return memory usage metrics for container environments."""
    try:
        current_bytes = read_int_file('/sys/fs/cgroup/memory.current')
        max_raw = read_text_file('/sys/fs/cgroup/memory.max')
        stat_content = read_text_file('/sys/fs/cgroup/memory.stat')
    except FileNotFoundError:
        return {
            'memory_available': False,
            'memory_message': 'This metric is only available when running inside a container.',
            'memory_usage': '',
            'memory_usage_number': '',
            'memory_usage_unit': '',
            'memory_limit': '',
            'memory_anon': '',
            'memory_file': '',
            'memory_kernel': '',
        }

    stat_values: dict[str, int] = {}
    for line in stat_content.splitlines():
        parts = line.split()
        if len(parts) >= MIN_PARTS_COUNT:
            key = parts[0]
            value = parts[1]
            if value.isdigit():
                stat_values[key] = int(value)

    current_display = format_bytes(current_bytes)
    current_number, current_unit = current_display.split(' ', 1)

    anon_display = format_bytes(stat_values.get('anon', 0))
    file_display = format_bytes(stat_values.get('file', 0))
    kernel_display = format_bytes(stat_values.get('kernel', 0))

    if max_raw == 'max':
        return {
            'memory_available': True,
            'memory_message': '',
            'memory_usage': current_display,
            'memory_usage_number': current_number,
            'memory_usage_unit': current_unit,
            'memory_limit': 'Unlimited',
            'memory_anon': anon_display,
            'memory_file': file_display,
            'memory_kernel': kernel_display,
        }

    limit_bytes = int(max_raw)
    limit_display = format_bytes(limit_bytes)

    return {
        'memory_available': True,
        'memory_message': '',
        'memory_usage': current_display,
        'memory_usage_number': current_number,
        'memory_usage_unit': current_unit,
        'memory_limit': limit_display,
        'memory_anon': anon_display,
        'memory_file': file_display,
        'memory_kernel': kernel_display,
    }


def get_disk_metrics() -> dict[str, str | bool]:
    """Return disk I/O metrics for container environments."""
    try:
        content = read_text_file('/sys/fs/cgroup/io.stat')
    except FileNotFoundError:
        return {
            'disk_available': False,
            'disk_message': 'This metric is only available when running inside a container.',
            'disk_read': '',
            'disk_write': '',
        }

    total_read_bytes = 0
    total_write_bytes = 0

    for line in content.splitlines():
        for part in line.split():
            if '=' in part:
                key, value = part.split('=', 1)
                if key == 'rbytes':
                    total_read_bytes += int(value)
                elif key == 'wbytes':
                    total_write_bytes += int(value)

    return {
        'disk_available': True,
        'disk_message': '',
        'disk_read': format_bytes(total_read_bytes),
        'disk_write': format_bytes(total_write_bytes),
    }


def get_network_metrics() -> dict[str, str | bool]:
    """Return network I/O metrics for container environments."""
    try:
        content = read_text_file('/proc/net/dev')
    except FileNotFoundError:
        return {
            'network_available': False,
            'network_message': 'This metric is only available when running inside a container.',
            'network_received': '',
            'network_transmitted': '',
        }

    for raw_line in content.splitlines():
        stripped_line = raw_line.strip()
        if stripped_line.startswith('eth0:'):
            _, data = stripped_line.split(':', 1)
            fields = data.split()

            received_bytes = int(fields[0])
            transmitted_bytes = int(fields[8])

            return {
                'network_available': True,
                'network_message': '',
                'network_received': format_bytes(received_bytes),
                'network_transmitted': format_bytes(transmitted_bytes),
            }

    return {
        'network_available': False,
        'network_message': 'No container network interface was found.',
        'network_received': '',
        'network_transmitted': '',
    }


def get_workflow_execution_form(request: HttpRequest) -> WorkflowExecutionConfigForm:
    """Return the singleton Workflow 2 execution settings form."""
    workflow_config = WorkflowExecutionConfig.load()
    if request.method == 'POST' and request.POST.get('form_name') == 'workflow_execution':
        return WorkflowExecutionConfigForm(request.POST, instance=workflow_config)
    return WorkflowExecutionConfigForm(instance=workflow_config)


def build_workflow_execution_context(
    request: HttpRequest,
    workflow_execution_form: WorkflowExecutionConfigForm | None = None,
) -> dict[str, Any]:
    """Build the workflow execution settings context for the tabbed settings page."""
    workflow_execution_form = workflow_execution_form or get_workflow_execution_form(request)
    workflow_config = workflow_execution_form.instance
    stale_after = int(getattr(workflow_config, 'worker_stale_after_seconds', 30) or 30)
    cutoff = now() - timedelta(seconds=stale_after)
    latest = Workflow2WorkerHeartbeat.objects.order_by('-last_seen').first()
    any_alive = Workflow2WorkerHeartbeat.objects.filter(last_seen__gte=cutoff).exists()

    return {
        'workflow_execution_form': workflow_execution_form,
        'workflow_worker_any_alive': any_alive,
        'workflow_worker_latest_id': getattr(latest, 'worker_id', None),
        'workflow_worker_latest_seen': getattr(latest, 'last_seen', None),
        'workflow_worker_stale_after_seconds': stale_after,
        'workflow_inline_takeover_enabled': str(workflow_config.mode).lower() in {
            WorkflowExecutionConfig.Mode.AUTO,
            WorkflowExecutionConfig.Mode.INLINE,
        },
    }


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
        context['active_tab'] = kwargs.get('active_tab', self.request.GET.get('tab', 'internationalization'))

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

        metrics_view = MetricsSettingsView()
        metrics_view.request = self.request
        metrics_view.setup(self.request)
        metrics_context = metrics_view.get_context_data()

        context['uptime'] = metrics_context['uptime']
        context['started_time'] = metrics_context['started_time']
        context['database_size'] = metrics_context['database_size']
        context['started_time_ts'] = int(APP_STARTED_AT.timestamp())

        context.update(get_memory_metrics())
        context.update(get_disk_metrics())
        context.update(get_network_metrics())

        return context
        workflow_execution_form = kwargs.get('workflow_execution_form')
        context.update(build_workflow_execution_context(self.request, workflow_execution_form))
        return context

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle inline Workflow 2 execution settings updates from the settings tab page."""
        if request.POST.get('form_name') != 'workflow_execution':
            return redirect(reverse_lazy('management:settings'))

        workflow_execution_form = get_workflow_execution_form(request)
        if workflow_execution_form.is_valid():
            workflow_execution_form.save()
            messages.success(request, _('Workflow execution settings saved.'))
            return redirect(f"{reverse_lazy('management:settings')}?tab=workflow")

        messages.error(request, _('Please correct the workflow execution settings errors.'))
        context = self.get_context_data(
            workflow_execution_form=workflow_execution_form,
            active_tab='workflow',
        )
        return self.render_to_response(context)


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

        messages.success(self.request, _('Internationalization configuration saved successfully.'))
        return response


class SecuritySettingsView(SettingsFormViewMixin[SecurityConfigForm]):
    """View for managing security settings."""

    template_name = 'management/includes/security_configuration.html'
    form_class = SecurityConfigForm
    setting_type = 'security'
    success_url = reverse_lazy('management:settings-security')

    def get_form_kwargs(self) -> dict[str, Any]:
        """Get the keyword arguments for instantiating the form."""
        kwargs = super().get_form_kwargs()
        try:
            security_config = SecurityConfig.objects.get(id=1)
        except SecurityConfig.DoesNotExist:
            security_config = SecurityConfig.objects.create()
        kwargs['instance'] = security_config
        return kwargs

    def form_valid(self, form: SecurityConfigForm) -> HttpResponse:
        """Handle valid security form submission."""
        old_conf = SecurityConfig.objects.get(pk=form.instance.pk) if form.instance.pk else None
        form.save()

        security_mode_display = form.instance.get_security_mode_display()
        actor = self.request.user if self.request.user.is_authenticated else None
        AuditLog.create_entry(
            operation_type=AuditLog.OperationType.SECURITY_CONFIG_CHANGED,
            target=form.instance,
            target_display=f'SecurityConfig: {security_mode_display}',
            actor=actor,
        )

        if 'security_mode' in form.changed_data:
            old_value = getattr(old_conf, 'security_mode', None) if old_conf else None
            new_value = form.cleaned_data.get('security_mode')

            if new_value is None:
                messages.error(self.request, 'Security mode value is missing.')
                return redirect(self.success_url)

            old_int = int(old_value) if old_value is not None else 0
            new_int = int(new_value)

            if new_int > old_int:
                self.sec.reset_settings(new_value)



        if 'auto_gen_pki' in form.changed_data:
            old_auto = getattr(old_conf, 'auto_gen_pki', None) if old_conf else None
            new_auto = form.cleaned_data.get('auto_gen_pki', None)
            self.logger.info('auto_gen_pki changed: old=%s, new=%s', old_auto, new_auto)

            if old_auto != new_auto and new_auto:
                key_alg_value = form.cleaned_data.get('auto_gen_pki_key_algorithm')
                if key_alg_value is None:
                    messages.error(self.request, 'Auto-generated PKI key algorithm is missing.')
                    return redirect(self.success_url)
                key_alg = AutoGenPkiKeyAlgorithm(key_alg_value)
                self.logger.info('Calling enable_feature for AutoGenPkiFeature with key_alg: %s', key_alg)
                self.sec.enable_feature(AutoGenPkiFeature, {'key_algorithm': key_alg})
                self.logger.info('Auto-generated PKI enabled with key algorithm: %s', key_alg.name)

            elif old_auto != new_auto and not new_auto:
                AutoGenPkiFeature.disable()
                self.logger.info('Auto-generated PKI disabled')

        messages.success(self.request, _('Your changes were saved successfully.'))
        return redirect(self.get_success_url())

    def form_invalid(self, form: SecurityConfigForm) -> HttpResponse:
        """Handle invalid security form submission."""
        messages.error(self.request, _('Error saving the configuration'))
        extra: dict[str, Any] = {'form': form}


        self.template_name = 'management/settings.html'
        context = self.get_context_data(**extra)
        context['active_tab'] = 'security'
        context['security_form'] = form


        internationalization_view = InternationalizationSettingsView()
        internationalization_view.request = self.request
        internationalization_view.setup(self.request)
        context['internationalization_form'] = internationalization_view.get_form()

        logging_view = LoggingSettingsView()
        logging_view.request = self.request
        logging_view.setup(self.request)
        context['logging_form'] = logging_view.get_form()
        context['loglevels'] = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        context['current_loglevel'] = logging.getLevelName(logging.getLogger().getEffectiveLevel())

        notification_view = NotificationSettingsView()
        notification_view.request = self.request
        notification_view.setup(self.request)
        context['notification_form'] = notification_view.get_form()
        context['notification_config'] = NotificationConfig.get()

        return self.render_to_response(context)

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
            defaults={'log_level': level},
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
                            _('Notifications enabled and notification cycle initialized.'),
                        )
                    else:
                        messages.success(
                            self.request,
                            _('Notification configuration saved and cycle reinitialized.'),
                        )
                except Exception:
                    self.logger.exception('Error initializing notifications')
                    messages.error(
                        self.request,
                        _('Notifications saved but error initializing notification cycle.'),
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


class MetricsSettingsView(TemplateView):
    """View for displaying runtime metrics."""

    template_name = 'management/includes/metrics_configuration.html'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Build the context dictionary for the metrics settings page."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'management'
        context['page_name'] = 'settings'
        context['setting_type'] = 'metrics'

        context['uptime'] = format_uptime(APP_STARTED_AT)
        context['started_time'] = APP_STARTED_AT
        context['database_size'] = get_database_size()
        return context

class ChangeLogLevelView(View):
    """Deprecated view for changing the logging level."""

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle POST requests to change the logging level."""
        form = LoggingConfigForm(request.POST)
        if not form.is_valid():
            normalized_data = request.POST.copy()
            normalized_data['loglevel'] = (normalized_data.get('loglevel') or '').upper()
            form = LoggingConfigForm(normalized_data)

        if form.is_valid():
            form.save()
            messages.success(request, _('Log level updated successfully.'))
        else:
            messages.error(request, _('Invalid log level.'))

        return redirect(reverse_lazy('management:settings') + '?tab=log')
