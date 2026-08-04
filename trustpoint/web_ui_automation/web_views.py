# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Web views for Web UI automation devices, profiles, assignments, and jobs."""

from __future__ import annotations

import contextlib
import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from django import db
from django.contrib import messages
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.dateparse import parse_datetime
from django.views import View
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from trustpoint.logger import LoggerMixin
from trustpoint.page_context import DEVICES_PAGE_CATEGORY, DEVICES_PAGE_WEB_AUTOMATION_SUBCATEGORY, PageContextMixin
from web_ui_automation.audit import WebUiAuditOperation, write_audit_entry
from web_ui_automation.executor import execute_job
from web_ui_automation.forms import (
    ConfirmExecutionForm,
    EnableAutomaticRenewalForm,
    WebUiAutomationAssignmentForm,
    WebUiAutomationDeviceCreateForm,
    WebUiAutomationDeviceUpdateForm,
    WebUiAutomationProfileForm,
)
from web_ui_automation.models import (
    AutomationOperation,
    WebUiAutomationAssignedProfile,
    WebUiAutomationDevice,
    WebUiAutomationJob,
    WebUiAutomationProfileDefinition,
)
from web_ui_automation.orchestration import queue_operation
from web_ui_automation.services import confirm_job, disable_automatic_renewal, enable_automatic_renewal

if TYPE_CHECKING:
    from django.db.models import QuerySet


class WebUiPageMixin(PageContextMixin):
    """Use the existing devices/agents navigation category for the initial integration."""

    page_category = DEVICES_PAGE_CATEGORY
    page_name = DEVICES_PAGE_WEB_AUTOMATION_SUBCATEGORY


class AutomationDeviceListView(WebUiPageMixin, LoggerMixin, ListView[WebUiAutomationDevice]):
    """List Web UI automation device configurations."""

    http_method_names: ClassVar[list[str]] = ['get']
    model = WebUiAutomationDevice
    template_name = 'web_ui_automation/device_list.html'
    context_object_name = 'automation_devices'
    paginate_by = 25

    def get_queryset(self) -> QuerySet[WebUiAutomationDevice]:
        """Return devices with their linked Trustpoint device."""
        return WebUiAutomationDevice.objects.select_related('device').order_by('device__common_name')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add URLs for bulk delete/revoke operations."""
        context = super().get_context_data(**kwargs)
        context['device_revoke_url'] = reverse('web_ui_automation:device-revoke')
        context['device_delete_url'] = reverse('web_ui_automation:device-delete')
        return context


class AutomationDeviceCreateView(
    WebUiPageMixin,
    LoggerMixin,
    CreateView[WebUiAutomationDevice, WebUiAutomationDeviceCreateForm],
):
    """Create a Web UI automation device and encrypted credential set."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationDevice
    form_class = WebUiAutomationDeviceCreateForm
    template_name = 'web_ui_automation/form.html'
    success_url = reverse_lazy('web_ui_automation:devices')
    extra_context: ClassVar[dict[str, str]] = {'title': 'Create Web UI Automation Device'}

    def form_valid(self, form: WebUiAutomationDeviceCreateForm) -> HttpResponse:
        """Save and audit a new device configuration."""
        response = super().form_valid(form)
        write_audit_entry(WebUiAuditOperation.DEVICE_CONFIGURED, self.object, actor=self.request.user)
        messages.success(self.request, 'Web UI automation device created.')
        return response


class AutomationDeviceDeleteView(WebUiPageMixin, LoggerMixin, ListView[WebUiAutomationDevice]):
    """Delete Web UI automation devices (supports bulk operations)."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationDevice
    template_name = 'web_ui_automation/device_confirm_delete.html'
    context_object_name = 'automation_devices'

    pks: str = ''
    queryset: QuerySet[WebUiAutomationDevice]

    def get_queryset(self) -> QuerySet[WebUiAutomationDevice]:
        """Get the devices to delete based on pks parameter."""
        if not self.pks:
            self.pks = self.kwargs.get('pks', '')

        if not self.pks:
            return WebUiAutomationDevice.objects.none()

        pk_list = [int(pk) for pk in self.pks.split('/') if pk.isdigit()]
        return WebUiAutomationDevice.objects.filter(pk__in=pk_list).select_related('device')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add pks to context."""
        context = super().get_context_data(**kwargs)
        context['pks'] = self.pks
        return context

    def get(self, request: HttpRequest, pks: str | None = None, **kwargs: Any) -> HttpResponse:
        """Show confirmation page for deletion."""
        self.pks = pks or ''

        if not self.pks:
            messages.error(request, 'No device IDs provided.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, 'No valid devices found to delete.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        return super().get(request, **kwargs)

    def post(self, request: HttpRequest, pks: str | None = None) -> HttpResponse:
        """Delete automation devices and associated data.

        Args:
            request: HTTP request object
            pks: Slash-separated string of primary keys (e.g., "1/2/3"), or None
        """
        self.pks = pks or ''

        if not self.pks:
            messages.error(request, 'No device IDs provided.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        pk_list = [int(pk) for pk in self.pks.split('/') if pk.isdigit()]

        if not pk_list:
            messages.error(request, 'No valid device IDs provided.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        automation_devices = WebUiAutomationDevice.objects.filter(pk__in=pk_list).select_related('device')
        deleted_count = 0

        for automation_device in automation_devices:
            device = automation_device.device
            device_name = device.common_name if device else str(automation_device)

            automation_device.delete()

            if device:
                device.delete()

            write_audit_entry(
                WebUiAuditOperation.DEVICE_DELETED,
                None,
                actor=request.user,
                details=f'Deleted device: {device_name}'
            )
            deleted_count += 1

        if deleted_count > 0:
            messages.success(request, f'Successfully deleted {deleted_count} Web UI automation device(s).')
        else:
            messages.error(request, 'No devices were deleted.')

        return HttpResponseRedirect(reverse('web_ui_automation:devices'))


class AutomationDeviceRevokeView(WebUiPageMixin, LoggerMixin, ListView[WebUiAutomationDevice]):
    """Revoke all certificates for Web UI automation devices (supports bulk operations)."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationDevice
    template_name = 'web_ui_automation/device_confirm_revoke.html'
    context_object_name = 'automation_devices'

    pks: str = ''
    queryset: QuerySet[WebUiAutomationDevice]

    def get_queryset(self) -> QuerySet[WebUiAutomationDevice]:
        """Get the devices to revoke based on pks parameter."""
        if not self.pks:
            self.pks = self.kwargs.get('pks', '')

        if not self.pks:
            return WebUiAutomationDevice.objects.none()

        pk_list = [int(pk) for pk in self.pks.split('/') if pk.isdigit()]
        return WebUiAutomationDevice.objects.filter(pk__in=pk_list).select_related('device').prefetch_related(
            'assigned_profiles__issued_credential__credential__certificate'
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add pks to context."""
        context = super().get_context_data(**kwargs)
        context['pks'] = self.pks
        return context

    def get(self, request: HttpRequest, pks: str | None = None, **kwargs: Any) -> HttpResponse:
        """Show confirmation page for revocation."""
        self.pks = pks or ''

        if not self.pks:
            messages.error(request, 'No device IDs provided.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        queryset = self.get_queryset()
        if not queryset.exists():
            messages.error(request, 'No valid devices found to revoke.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        return super().get(request, **kwargs)

    def post(self, request: HttpRequest, pks: str | None = None) -> HttpResponse:
        """Revoke all certificates associated with devices' assignments.

        Args:
            request: HTTP request object
            pks: Slash-separated string of primary keys (e.g., "1/2/3"), or None
        """
        self.pks = pks or ''

        if not self.pks:
            messages.error(request, 'No device IDs provided.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        pk_list = [int(pk) for pk in self.pks.split('/') if pk.isdigit()]

        if not pk_list:
            messages.error(request, 'No valid device IDs provided.')
            return HttpResponseRedirect(reverse('web_ui_automation:devices'))

        automation_devices = WebUiAutomationDevice.objects.filter(pk__in=pk_list).prefetch_related(
            'assigned_profiles__issued_credential__credential__certificate'
        )

        total_revoked = 0

        for automation_device in automation_devices:
            revoked_count = 0

            assignments = automation_device.assigned_profiles.all()

            for assignment in assignments:
                if assignment.current_certificate:
                    # TODO (FHK): Actual certificate revocation logic to be implemented  # noqa: FIX002
                    revoked_count += 1

            total_revoked += revoked_count

        if total_revoked > 0:
            messages.success(
                request,
                f'Initiated revocation for {total_revoked} certificate(s) across {len(pk_list)} device(s).',
            )
        else:
            messages.info(request, 'No certificates to revoke for the selected device(s).')

        return HttpResponseRedirect(reverse('web_ui_automation:devices'))


class AutomationProfileListView(WebUiPageMixin, LoggerMixin, ListView[WebUiAutomationProfileDefinition]):
    """List Web UI automation profile definitions."""

    http_method_names: ClassVar[list[str]] = ['get']
    model = WebUiAutomationProfileDefinition
    template_name = 'web_ui_automation/profile_list.html'
    context_object_name = 'profiles'
    paginate_by = 25


class AutomationProfileCreateView(
    WebUiPageMixin,
    LoggerMixin,
    CreateView[WebUiAutomationProfileDefinition, WebUiAutomationProfileForm],
):
    """Create and schema-validate a custom automation profile."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationProfileDefinition
    form_class = WebUiAutomationProfileForm
    template_name = 'web_ui_automation/profile_config.html'
    success_url = reverse_lazy('web_ui_automation:profiles')
    extra_context: ClassVar[dict[str, str]] = {'title': 'Create Web UI Automation Profile'}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data for JSON editor."""
        context = super().get_context_data(**kwargs)
        form = context['form']

        raw_json = form['profile'].value() or None

        if not self.object or not self.object.pk:
            context['is_new'] = True

        context['json_valid'] = True

        if not raw_json or raw_json == 'null':
            context['profile_json'] = self._default_profile_json()
            return context

        if isinstance(raw_json, dict):
            context['profile_json'] = raw_json
            return context

        if isinstance(raw_json, str):
            cleaned_raw = raw_json.encode('utf-8').decode('unicode_escape')
            if cleaned_raw.startswith('"') and cleaned_raw.endswith('"'):
                cleaned_raw = cleaned_raw[1:-1]

            with contextlib.suppress(json.JSONDecodeError):
                parsed = json.loads(cleaned_raw)
                if isinstance(parsed, dict):
                    context['profile_json'] = parsed
                    return context

            with contextlib.suppress(json.JSONDecodeError):
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    context['profile_json'] = parsed
                    return context

        context['json_valid'] = False
        context['profile_json'] = str(raw_json)
        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        if self.object and self.object.pk:
            initial['name'] = self.object.name
            if self.object.profile:
                initial['profile'] = json.dumps(self.object.profile)
            else:
                initial['profile'] = self._default_profile_json()
        else:
            initial['profile'] = self._default_profile_json()
        return initial

    @staticmethod
    def _default_profile_json() -> str:
        """Load default profile from JSON file."""
        default_profile_path = Path(__file__).parent / 'default_profiles' / 'minimal_default.json'
        try:
            with default_profile_path.open('r', encoding='utf-8') as f:
                profile_data = json.load(f)
                return json.dumps(profile_data, indent=2)
        except (FileNotFoundError, json.JSONDecodeError):
            # Fallback to minimal profile if file doesn't exist or is invalid
            return json.dumps({
                'schema': 'trustpoint.web-automation.v1',
                'name': 'New Profile',
                'version': '1.0.0',
                'metadata': {
                    'vendor': 'Generic',
                    'device_family': 'Device',
                    'description': 'Custom profile',
                },
                'operations': {},
            }, indent=2)

    def form_valid(self, form: WebUiAutomationProfileForm) -> HttpResponse:
        """Save and audit the profile."""
        profile_data = form.cleaned_data.get('profile')
        if isinstance(profile_data, str):
            try:
                parsed_profile = json.loads(profile_data)
                if not isinstance(parsed_profile, dict):
                    form.add_error('profile', 'Profile must be a JSON object.')
                    return self.form_invalid(form)
                form.instance.profile = parsed_profile
            except json.JSONDecodeError as exc:
                form.add_error('profile', f'Invalid JSON: {exc}')
                return self.form_invalid(form)

        response = super().form_valid(form)
        write_audit_entry(WebUiAuditOperation.PROFILE_CREATED, self.object, actor=self.request.user)
        messages.success(self.request, 'Automation profile created and validated.')
        return response


class AutomationProfileUpdateView(
    WebUiPageMixin,
    LoggerMixin,
    UpdateView[WebUiAutomationProfileDefinition, WebUiAutomationProfileForm],
):
    """Edit a custom automation profile in place."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationProfileDefinition
    form_class = WebUiAutomationProfileForm
    template_name = 'web_ui_automation/profile_config.html'
    success_url = reverse_lazy('web_ui_automation:profiles')
    extra_context: ClassVar[dict[str, str]] = {'title': 'Edit Web UI Automation Profile'}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context data for JSON editor."""
        context = super().get_context_data(**kwargs)
        form = context['form']

        raw_json = form['profile'].value() or None

        context['json_valid'] = True

        if not raw_json or raw_json == 'null':
            context['profile_json'] = self._default_profile_json()
            return context

        if isinstance(raw_json, dict):
            context['profile_json'] = raw_json
            return context

        if isinstance(raw_json, str):
            cleaned_raw = raw_json.encode('utf-8').decode('unicode_escape')
            if cleaned_raw.startswith('"') and cleaned_raw.endswith('"'):
                cleaned_raw = cleaned_raw[1:-1]

            with contextlib.suppress(json.JSONDecodeError):
                parsed = json.loads(cleaned_raw)
                if isinstance(parsed, dict):
                    context['profile_json'] = parsed
                    return context

            with contextlib.suppress(json.JSONDecodeError):
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    context['profile_json'] = parsed
                    return context

        context['json_valid'] = False
        context['profile_json'] = str(raw_json)
        return context

    def get_initial(self) -> dict[str, Any]:
        """Initialize the form with default values."""
        initial = super().get_initial()
        if self.object and self.object.pk:
            initial['name'] = self.object.name
            if self.object.profile:
                initial['profile'] = json.dumps(self.object.profile)
            else:
                initial['profile'] = self._default_profile_json()
        return initial

    @staticmethod
    def _default_profile_json() -> str:
        """Load default profile from JSON file."""
        default_profile_path = Path(__file__).parent / 'default_profiles' / 'minimal_default.json'
        try:
            with default_profile_path.open('r', encoding='utf-8') as f:
                profile_data = json.load(f)
                return json.dumps(profile_data, indent=2)
        except (FileNotFoundError, json.JSONDecodeError):
            return json.dumps({
                'schema': 'trustpoint.web-automation.v1',
                'name': 'New Profile',
                'version': '1.0.0',
                'metadata': {
                    'vendor': 'Generic',
                    'device_family': 'Device',
                    'description': 'Custom profile',
                },
                'operations': {},
            }, indent=2)

    def form_valid(self, form: WebUiAutomationProfileForm) -> HttpResponse:
        """Save and audit a profile change."""
        # Parse JSON if needed
        profile_data = form.cleaned_data.get('profile')
        if isinstance(profile_data, str):
            try:
                parsed_profile = json.loads(profile_data)
                if not isinstance(parsed_profile, dict):
                    form.add_error('profile', 'Profile must be a JSON object.')
                    return self.form_invalid(form)
                form.instance.profile = parsed_profile
            except json.JSONDecodeError as exc:
                form.add_error('profile', f'Invalid JSON: {exc}')
                return self.form_invalid(form)

        response = super().form_valid(form)
        write_audit_entry(
            WebUiAuditOperation.PROFILE_UPDATED,
            self.object,
            actor=self.request.user,
            details={'checksum': self.object.checksum},
        )
        messages.success(self.request, 'Profile updated. Automatic renewal was disabled for assigned devices.')
        return response


class AssignedProfileListView(WebUiPageMixin, LoggerMixin, ListView[WebUiAutomationAssignedProfile]):
    """List profiles assigned to one Web UI automation device."""

    http_method_names: ClassVar[list[str]] = ['get']
    model = WebUiAutomationAssignedProfile
    template_name = 'web_ui_automation/assignment_list.html'
    context_object_name = 'assignments'
    paginate_by = 25

    def get_queryset(self) -> QuerySet[WebUiAutomationAssignedProfile]:
        """Return assignments for the selected automation device."""
        return WebUiAutomationAssignedProfile.objects.filter(
            automation_device_id=self.kwargs['device_id']
        ).select_related('workflow_definition', 'issued_credential')

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the parent device to the template context."""
        context = super().get_context_data(**kwargs)
        context['automation_device'] = get_object_or_404(WebUiAutomationDevice, pk=self.kwargs['device_id'])
        return context


class AssignedProfileCreateView(
    WebUiPageMixin,
    LoggerMixin,
    CreateView[WebUiAutomationAssignedProfile, WebUiAutomationAssignmentForm],
):
    """Assign a profile to a Web UI automation device."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationAssignedProfile
    form_class = WebUiAutomationAssignmentForm
    template_name = 'web_ui_automation/form.html'
    extra_context: ClassVar[dict[str, str]] = {'title': 'Assign Web UI Automation Profile'}

    def get_initial(self) -> dict[str, Any]:
        """Preselect the parent automation device."""
        initial = super().get_initial()
        initial['automation_device'] = self.kwargs['device_id']
        return initial

    def get_success_url(self) -> str:
        """Return to the selected device CLM view."""
        return reverse('web_ui_automation:device-clm', kwargs={'pk': self.kwargs['device_id']})

    def form_valid(self, form: WebUiAutomationAssignmentForm) -> HttpResponse:
        """Ensure that the assignment belongs to the URL device."""
        form.instance.automation_device = get_object_or_404(WebUiAutomationDevice, pk=self.kwargs['device_id'])
        messages.success(self.request, 'Automation profile assigned.')
        return super().form_valid(form)


class AssignedProfileUpdateView(
    WebUiPageMixin,
    LoggerMixin,
    UpdateView[WebUiAutomationAssignedProfile, WebUiAutomationAssignmentForm],
):
    """Update assignment and renewal scheduling settings."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationAssignedProfile
    form_class = WebUiAutomationAssignmentForm
    template_name = 'web_ui_automation/form.html'
    extra_context: ClassVar[dict[str, str]] = {'title': 'Edit Assigned Automation Profile'}

    def get_queryset(self) -> QuerySet[WebUiAutomationAssignedProfile]:
        """Restrict updates to the parent automation device."""
        return WebUiAutomationAssignedProfile.objects.filter(automation_device_id=self.kwargs['device_id'])

    def get_success_url(self) -> str:
        """Return to the parent device CLM view."""
        return reverse('web_ui_automation:device-clm', kwargs={'pk': self.kwargs['device_id']})


class AssignedProfileDeleteView(WebUiPageMixin, LoggerMixin, View):
    """Delete an assigned profile."""

    http_method_names: ClassVar[list[str]] = ['post']

    def post(self, request: HttpRequest, device_id: int, pk: int) -> HttpResponse:
        """Delete the profile assignment.

        Args:
            request: HTTP request object
            device_id: The automation device ID
            pk: The assignment ID
        """
        assignment = get_object_or_404(
            WebUiAutomationAssignedProfile,
            pk=pk,
            automation_device_id=device_id
        )

        profile_name = assignment.workflow_definition.name
        assignment.delete()

        messages.success(request, f'Profile assignment "{profile_name}" has been deleted.')
        return HttpResponseRedirect(reverse('web_ui_automation:device-clm', kwargs={'pk': device_id}))


class AutomationJobDetailView(WebUiPageMixin, LoggerMixin, DetailView[WebUiAutomationJob]):
    """Display a job result and sanitized step logs."""

    http_method_names: ClassVar[list[str]] = ['get']
    model = WebUiAutomationJob
    template_name = 'web_ui_automation/job_detail.html'
    context_object_name = 'job'

    def get_queryset(self) -> QuerySet[WebUiAutomationJob]:
        """Load job relations used by the detail page."""
        return WebUiAutomationJob.objects.select_related(
            'assignment__automation_device',
            'assignment__workflow_definition',
        ).prefetch_related('step_logs')


class StartOperationView(WebUiPageMixin, LoggerMixin, View):
    """Queue onboarding, renewal, or inventory for one assigned profile."""

    http_method_names: ClassVar[list[str]] = ['post']

    def post(self, request: HttpRequest, pk: int, operation: str) -> HttpResponse:
        """Prepare and enqueue the selected operation."""
        assignment = get_object_or_404(WebUiAutomationAssignedProfile, pk=pk)
        device_id = assignment.automation_device_id

        if operation not in AutomationOperation.values:
            messages.error(request, 'Unknown automation operation.')
            return HttpResponseRedirect(reverse('web_ui_automation:device-clm', kwargs={'pk': device_id}))

        existing_job = WebUiAutomationJob.objects.filter(
            assignment=assignment,
            operation=operation,
            status__in=['QUEUED', 'RUNNING']
        ).first()

        if existing_job:
            messages.warning(
                request,
                f'A {operation} job is already {existing_job.get_status_display().lower()}. '
                f'Please wait for it to complete or view its status.'
            )
            return HttpResponseRedirect(reverse('web_ui_automation:job-detail', kwargs={'pk': existing_job.pk}))

        failed_job = WebUiAutomationJob.objects.filter(
            assignment=assignment,
            operation=operation,
            status='FAILED'
        ).order_by('-created_at').first()

        try:
            job = queue_operation(assignment, operation, actor=request.user, is_automatic=False)
        except (ImproperlyConfigured, ValidationError) as exc:
            messages.error(request, str(exc))
            return HttpResponseRedirect(reverse('web_ui_automation:device-clm', kwargs={'pk': device_id}))

        if failed_job:
            messages.success(
                request,
                f'Automation job {job.pk} queued. Retrying after previous failed job {failed_job.pk}.'
            )
        else:
            messages.success(request, f'Automation job {job.pk} queued.')
        return HttpResponseRedirect(reverse('web_ui_automation:job-detail', kwargs={'pk': job.pk}))


class ConfirmJobView(WebUiPageMixin, LoggerMixin, View):
    """Confirm a completed onboarding or manual renewal execution."""

    http_method_names: ClassVar[list[str]] = ['post']

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Validate confirmation and apply the lifecycle transition."""
        job = get_object_or_404(WebUiAutomationJob, pk=pk)
        form = ConfirmExecutionForm(request.POST)
        if form.is_valid():
            confirm_job(job, actor=request.user)
            messages.success(request, 'The certificate operation was confirmed.')
        else:
            messages.error(request, 'The confirmation could not be applied.')
        return HttpResponseRedirect(reverse('web_ui_automation:job-detail', kwargs={'pk': pk}))


class ExecuteJobNowView(WebUiPageMixin, LoggerMixin, View):
    """Execute a queued job immediately, bypassing the queue."""

    http_method_names: ClassVar[list[str]] = ['post']

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Execute the job immediately if it's in QUEUED state."""
        job = get_object_or_404(WebUiAutomationJob, pk=pk)

        if job.status != 'QUEUED':
            messages.error(request, f'Job cannot be executed. Current status: {job.get_status_display()}')
            return HttpResponseRedirect(reverse('web_ui_automation:job-detail', kwargs={'pk': pk}))

        def run_job() -> None:
            """Run the job in a separate thread with proper database connection."""
            db.connections.close_all()
            try:
                execute_job(job.pk)
            finally:
                db.connections.close_all()

        thread = threading.Thread(target=run_job, daemon=True)
        thread.start()

        messages.success(request, 'Job execution started in background.')
        return HttpResponseRedirect(reverse('web_ui_automation:job-detail', kwargs={'pk': pk}))


class EnableAutomaticRenewalView(WebUiPageMixin, LoggerMixin, View):
    """Explicitly enable automatic renewal for one assignment."""

    http_method_names: ClassVar[list[str]] = ['post']

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Enable renewal after validating all safety preconditions."""
        assignment = get_object_or_404(WebUiAutomationAssignedProfile, pk=pk)
        form = EnableAutomaticRenewalForm(assignment, request.POST)
        if form.is_valid():
            enable_automatic_renewal(assignment, actor=request.user)
            messages.success(request, 'Automatic renewal enabled.')
        else:
            messages.error(request, '; '.join(form.non_field_errors()))
        return HttpResponseRedirect(
            reverse('web_ui_automation:assignments', kwargs={'device_id': assignment.automation_device_id})
        )


class DisableAutomaticRenewalView(WebUiPageMixin, LoggerMixin, View):
    """Disable automatic renewal for one assignment."""

    http_method_names: ClassVar[list[str]] = ['post']

    def post(self, request: HttpRequest, pk: int) -> HttpResponse:
        """Disable renewal and audit the explicit user action."""
        assignment = get_object_or_404(WebUiAutomationAssignedProfile, pk=pk)
        disable_automatic_renewal(assignment, actor=request.user, reason='Disabled by user')
        messages.success(request, 'Automatic renewal disabled.')
        return HttpResponseRedirect(
            reverse('web_ui_automation:assignments', kwargs={'device_id': assignment.automation_device_id})
        )


class WebUiAutomationDeviceCLMView(WebUiPageMixin, LoggerMixin, DetailView[WebUiAutomationDevice]):
    """Certificate Lifecycle Management view for Web UI automation devices."""

    http_method_names: ClassVar[list[str]] = ['get', 'post']
    model = WebUiAutomationDevice
    template_name = 'web_ui_automation/device_clm.html'
    context_object_name = 'automation_device'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add assignments and related data to context."""
        context = super().get_context_data(**kwargs)
        automation_device = self.object

        assignments = WebUiAutomationAssignedProfile.objects.filter(
            automation_device=automation_device
        ).select_related('workflow_definition', 'issued_credential').prefetch_related('jobs').order_by('-created_at')

        assignments_with_jobs = []
        for assignment in assignments:
            last_onboard_job = assignment.jobs.filter(operation='onboard').order_by('-created_at').first()
            assignments_with_jobs.append({
                'assignment': assignment,
                'last_onboard_job': last_onboard_job,
            })

        context['assignments_with_jobs'] = assignments_with_jobs
        context['device'] = automation_device.device or None

        if 'device_form' not in context:
            context['device_form'] = WebUiAutomationDeviceUpdateForm(automation_device)

        return context

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle device configuration updates."""
        self.object = self.get_object()
        form = WebUiAutomationDeviceUpdateForm(self.object, request.POST)

        if form.is_valid():
            form.save()
            messages.success(request, 'Device configuration updated successfully.')
            return HttpResponseRedirect(
                reverse('web_ui_automation:device-clm', kwargs={'pk': self.object.pk})
            )

        context = self.get_context_data()
        context['device_form'] = form
        return self.render_to_response(context)


class RenewalConfigView(WebUiPageMixin, LoggerMixin, DetailView[WebUiAutomationAssignedProfile]):
    """View for configuring automatic renewal for an assigned profile."""

    model = WebUiAutomationAssignedProfile
    template_name = 'web_ui_automation/renewal_config.html'
    context_object_name = 'assignment'
    http_method_names: ClassVar[list[str]] = ['get', 'post']

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add device to context."""
        context = super().get_context_data(**kwargs)
        context['automation_device'] = self.object.automation_device
        return context

    def post(self, request: HttpRequest, device_id: int, pk: int) -> HttpResponse:
        """Save renewal configuration."""
        assignment = get_object_or_404(WebUiAutomationAssignedProfile, pk=pk, automation_device_id=device_id)

        assignment.automatic_renewal_enabled = request.POST.get('automatic_renewal_enabled') == 'on'
        assignment.renewal_mode = request.POST.get('renewal_mode', assignment.renewal_mode)
        assignment.renewal_days = int(request.POST.get('renewal_days', assignment.renewal_days))

        next_update = request.POST.get('next_certificate_update_scheduled')
        if next_update:
            assignment.next_certificate_update_scheduled = parse_datetime(next_update)
        else:
            assignment.next_certificate_update_scheduled = None

        try:
            assignment.full_clean()
            assignment.save()
            messages.success(request, 'Renewal configuration saved successfully.')
        except ValidationError as e:
            messages.error(request, f'Failed to save renewal configuration: {e}')

        return HttpResponseRedirect(
            reverse('web_ui_automation:renewal-config', kwargs={'device_id': device_id, 'pk': pk})
        )


class RevokeCertificateView(WebUiPageMixin, LoggerMixin, View):
    """View for revoking a certificate associated with an assigned profile."""

    http_method_names: ClassVar[list[str]] = ['post']

    def post(self, request: HttpRequest, device_id: int, pk: int) -> HttpResponse:
        """Revoke the certificate for the given assignment."""
        assignment = get_object_or_404(WebUiAutomationAssignedProfile, pk=pk, automation_device_id=device_id)

        if not assignment.current_certificate:
            messages.error(request, 'No certificate to revoke.')
            return HttpResponseRedirect(
                reverse('web_ui_automation:device-clm', kwargs={'pk': device_id})
            )

        # TODO (FHK): Certificate revocation logic to be implemented  # noqa: FIX002

        messages.success(request, f'Certificate revocation initiated for {assignment.workflow_definition.name}.')
        return HttpResponseRedirect(
            reverse('web_ui_automation:device-clm', kwargs={'pk': device_id})
        )

