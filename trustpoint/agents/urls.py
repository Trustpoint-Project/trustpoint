"""URL configuration for the agents application."""
from django.urls import path, re_path

from agents.web_views import (
    AgentAssignedProfileCreateView,
    AgentAssignedProfileDeleteView,
    AgentAssignedProfileTableView,
    AgentManagedDeviceCreateView,
    AgentManagedDeviceDeleteView,
    AgentManagedDeviceTableView,
    AgentWorkflowDefinitionBulkDeleteConfirmView,
    AgentWorkflowDefinitionConfigView,
    AgentWorkflowDefinitionTableView,
)

app_name = 'agents'

urlpatterns = [
    path('profiles/', AgentWorkflowDefinitionTableView.as_view(), name='profiles'),
    path('profiles/<int:pk>/', AgentWorkflowDefinitionConfigView.as_view(), name='profiles-config'),
    re_path(
        r'^profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        AgentWorkflowDefinitionBulkDeleteConfirmView.as_view(),
        name='profiles-delete_confirm',
    ),
    # Managed devices for 1-to-n agents
    path(
        '<int:agent_id>/targets/',
        AgentManagedDeviceTableView.as_view(),
        name='targets-list',
    ),
    path(
        '<int:agent_id>/targets/create/',
        AgentManagedDeviceCreateView.as_view(),
        name='targets-create',
    ),
    re_path(
        r'^(?P<agent_id>[0-9]+)/targets/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        AgentManagedDeviceDeleteView.as_view(),
        name='targets-delete_confirm',
    ),
    # Assigned profiles for 1-to-1 agents
    path(
        '<int:agent_id>/assigned-profiles/',
        AgentAssignedProfileTableView.as_view(),
        name='assigned-profiles-list',
    ),
    path(
        '<int:agent_id>/assigned-profiles/create/',
        AgentAssignedProfileCreateView.as_view(),
        name='assigned-profiles-create',
    ),
    re_path(
        r'^(?P<agent_id>[0-9]+)/assigned-profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        AgentAssignedProfileDeleteView.as_view(),
        name='assigned-profiles-delete_confirm',
    ),
]
