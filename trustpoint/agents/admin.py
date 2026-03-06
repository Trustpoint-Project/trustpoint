"""Admin registrations for the agents application."""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from django.contrib import admin

from agents.models import AgentCertificateTarget, AgentJob, AgentWorkflowDefinition, TrustpointAgent

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest


@admin.register(TrustpointAgent)
class TrustpointAgentAdmin(admin.ModelAdmin):
    """Admin for TrustpointAgent."""

    list_display = ('name', 'agent_id', 'is_active', 'poll_interval_seconds', 'last_seen_at')
    list_filter = ('is_active',)
    search_fields = ('name', 'agent_id', 'cell_location')
    readonly_fields = ('last_seen_at', 'created_at', 'updated_at')


@admin.register(AgentWorkflowDefinition)
class AgentWorkflowDefinitionAdmin(admin.ModelAdmin):
    """Admin for AgentWorkflowDefinition."""

    list_display = ('name', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active',)
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')


@admin.register(AgentCertificateTarget)
class AgentCertificateTargetAdmin(admin.ModelAdmin):
    """Admin for AgentCertificateTarget."""

    list_display: ClassVar = (
        'device', 'agent', 'certificate_profile', 'enabled', 'renewal_threshold_days', 'push_requested',
    )
    list_filter: ClassVar = ('enabled', 'push_requested')
    search_fields: ClassVar = ('device__common_name', 'agent__name')
    readonly_fields: ClassVar = ('created_at', 'updated_at')
    actions: ClassVar = ['request_push']

    @admin.action(description='Request immediate certificate push on next check-in')
    def request_push(self, request: HttpRequest, queryset: QuerySet) -> None:
        """Set push_requested=True for all selected targets."""
        updated = queryset.update(push_requested=True)
        self.message_user(request, f'{updated} target(s) flagged for immediate push.')


@admin.register(AgentJob)
class AgentJobAdmin(admin.ModelAdmin):
    """Admin for AgentJob."""

    list_display = ('pk', 'target', 'status', 'key_spec', 'started_at', 'completed_at')
    list_filter = ('status', 'key_spec')
    search_fields = ('target__device__common_name',)
    readonly_fields = ('started_at', 'completed_at', 'csr_pem', 'cert_pem', 'ca_bundle_pem')
