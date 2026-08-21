# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django admin registrations for Web UI automation models."""

from django.contrib import admin

from web_ui_automation.models import (
    WebUiAutomationAssignedProfile,
    WebUiAutomationDevice,
    WebUiAutomationJob,
    WebUiAutomationProfileDefinition,
    WebUiAutomationStepLog,
)


@admin.register(WebUiAutomationDevice)
class WebUiAutomationDeviceAdmin(admin.ModelAdmin[WebUiAutomationDevice]):
    """Admin configuration for automation devices."""

    list_display = ('device', 'base_url', 'authentication_type', 'updated_at')
    search_fields = ('device__common_name', 'base_url')
    readonly_fields = (
        'encrypted_username',
        'encrypted_password',
        'encrypted_private_key_password',
        'credentials_updated_at',
        'created_at',
        'updated_at',
    )


@admin.register(WebUiAutomationProfileDefinition)
class WebUiAutomationProfileDefinitionAdmin(admin.ModelAdmin[WebUiAutomationProfileDefinition]):
    """Admin configuration for automation profiles."""

    list_display = ('name', 'certificate_profile_slug', 'checksum', 'updated_at')
    search_fields = ('name',)
    readonly_fields = ('checksum', 'created_at', 'updated_at')


@admin.register(WebUiAutomationAssignedProfile)
class WebUiAutomationAssignedProfileAdmin(admin.ModelAdmin[WebUiAutomationAssignedProfile]):
    """Admin configuration for assigned profiles."""

    list_display = (
        'automation_device',
        'workflow_definition',
        'onboarding_status',
        'enabled',
        'automatic_renewal_enabled',
        'next_certificate_update',
    )
    list_filter = ('onboarding_status', 'enabled', 'automatic_renewal_enabled', 'renewal_mode')
    readonly_fields = ('confirmed_profile_checksum', 'created_at', 'updated_at')


class WebUiAutomationStepLogInline(admin.TabularInline[WebUiAutomationStepLog, WebUiAutomationJob]):
    """Read-only step logs shown on automation jobs."""

    model = WebUiAutomationStepLog
    extra = 0
    can_delete = False
    readonly_fields = (
        'sequence',
        'step_id',
        'action',
        'status',
        'message',
        'details',
        'started_at',
        'finished_at',
    )


@admin.register(WebUiAutomationJob)
class WebUiAutomationJobAdmin(admin.ModelAdmin[WebUiAutomationJob]):
    """Admin configuration for immutable automation jobs."""

    list_display = ('id', 'assignment', 'operation', 'status', 'result', 'created_at')
    list_filter = ('operation', 'status', 'result', 'is_automatic')
    readonly_fields = (
        'assignment',
        'operation',
        'status',
        'result',
        'verification_status',
        'profile_snapshot',
        'profile_checksum',
        'candidate_certificate',
        'initiated_by',
        'is_automatic',
        'failed_step_id',
        'failure_category',
        'error_message',
        'started_at',
        'finished_at',
        'created_at',
    )
    inlines = (WebUiAutomationStepLogInline,)

    def has_add_permission(self, _request: object) -> bool:
        """Prevent jobs from being fabricated through the admin interface."""
        return False
