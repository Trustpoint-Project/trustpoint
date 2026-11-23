# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Admin registrations for the agents application."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import admin

from agents.models import (
    AgentAssignedProfile,
    AgentProfileDefinition,
    TrustpointAgent,
)

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest


@admin.register(TrustpointAgent)
class TrustpointAgentAdmin(admin.ModelAdmin[TrustpointAgent]):
    """Admin for TrustpointAgent."""

    list_display = ('name', 'agent_id', 'is_active', 'poll_interval_seconds', 'last_seen_at')
    list_filter = ('is_active',)
    search_fields = ('name', 'agent_id', 'cell_location')
    readonly_fields = ('last_seen_at', 'created_at', 'updated_at')


@admin.register(AgentProfileDefinition)
class AgentProfileDefinitionAdmin(admin.ModelAdmin[AgentProfileDefinition]):
    """Admin for AgentProfileDefinition."""

    list_display = ('name', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active',)
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')

    def get_queryset(self, request: HttpRequest) -> QuerySet[AgentProfileDefinition]:
        """Keep the encrypted secret value out of the admin change list."""
        return super().get_queryset(request).defer('secrets')


@admin.register(AgentAssignedProfile)
class AgentAssignedProfileAdmin(admin.ModelAdmin[AgentAssignedProfile]):
    """Admin for AgentAssignedProfile."""

    list_display = (
        'agent',
        'workflow_definition',
        'renewal_threshold_days',
        'last_certificate_update',
        'next_certificate_update_scheduled',
        'enabled',
    )
    list_filter = ('enabled',)
    search_fields = ('agent__name', 'workflow_definition__name')
    readonly_fields = ('last_certificate_update', 'created_at', 'updated_at')

    def get_queryset(self, request: HttpRequest) -> QuerySet[AgentAssignedProfile]:
        """Select relations for the change list without decrypting workflow secrets."""
        return (
            super()
            .get_queryset(request)
            .select_related('agent', 'workflow_definition')
            .defer('workflow_definition__secrets')
        )

    fieldsets = (
        (
            None,
            {
                'fields': ('agent', 'workflow_definition', 'enabled'),
            },
        ),
        (
            'Certificate Settings',
            {
                'fields': ('subject', 'subject_alt_name'),
            },
        ),
        (
            'Renewal Settings',
            {
                'fields': ('renewal_threshold_days', 'last_certificate_update', 'next_certificate_update_scheduled'),
            },
        ),
        (
            'Timestamps',
            {
                'fields': ('created_at', 'updated_at'),
                'classes': ('collapse',),
            },
        ),
    )
    actions: list[str] = ['force_renewal']  # noqa: RUF012

    @admin.action(description='Force renewal on next check-in (set scheduled time to now)')
    def force_renewal(self, request: HttpRequest, queryset: Any) -> None:
        """Set next_certificate_update_scheduled to now for all selected profiles."""
        from django.utils import timezone  # noqa: PLC0415

        updated = queryset.update(next_certificate_update_scheduled=timezone.now())
        self.message_user(request, f'{updated} profile(s) scheduled for immediate renewal.')
