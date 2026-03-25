"""Admin registrations for the agents application."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import admin

from agents.models import (
    AgentAssignedProfile,
    AgentWorkflowDefinition,
    TrustpointAgent,
)

if TYPE_CHECKING:
    from django.http import HttpRequest


@admin.register(TrustpointAgent)
class TrustpointAgentAdmin(admin.ModelAdmin[TrustpointAgent]):
    """Admin for TrustpointAgent."""

    list_display = ('name', 'agent_id', 'is_active', 'poll_interval_seconds', 'last_seen_at')
    list_filter = ('is_active',)
    search_fields = ('name', 'agent_id', 'cell_location')
    readonly_fields = ('last_seen_at', 'created_at', 'updated_at')


@admin.register(AgentWorkflowDefinition)
class AgentWorkflowDefinitionAdmin(admin.ModelAdmin[AgentWorkflowDefinition]):
    """Admin for AgentWorkflowDefinition."""

    list_display = ('name', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active',)
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')


@admin.register(AgentAssignedProfile)
class AgentAssignedProfileAdmin(admin.ModelAdmin[AgentAssignedProfile]):
    """Admin for AgentAssignedProfile."""

    list_display = (
        'agent', 'workflow_definition', 'renewal_threshold_days',
        'last_certificate_update', 'next_certificate_update_scheduled', 'enabled',
    )
    list_filter = ('enabled',)
    search_fields = ('agent__name', 'workflow_definition__name')
    readonly_fields = ('last_certificate_update', 'created_at', 'updated_at')
    actions: list[str] = ['force_renewal']  # noqa: RUF012

    @admin.action(description='Force renewal on next check-in (set scheduled time to now)')
    def force_renewal(self, request: HttpRequest, queryset: Any) -> None:
        """Set next_certificate_update_scheduled to now for all selected profiles."""
        from django.utils import timezone  # noqa: PLC0415

        updated = queryset.update(next_certificate_update_scheduled=timezone.now())
        self.message_user(request, f'{updated} profile(s) scheduled for immediate renewal.')
