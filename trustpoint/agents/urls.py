# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""URL configuration for the agents application."""
from django.urls import path, re_path

from agents.web_views import (
    AgentAssignedProfileCreateView,
    AgentAssignedProfileDeleteView,
    AgentAssignedProfileEditView,
    AgentAssignedProfileForceUpdateView,
    AgentAssignedProfileTableView,
    AgentProfileDefinitionBulkDeleteConfirmView,
    AgentProfileDefinitionConfigView,
    AgentProfileDefinitionTableView,
)

app_name = 'agents'

urlpatterns = [
    path('profiles/', AgentProfileDefinitionTableView.as_view(), name='profiles'),
    path('profiles/create/', AgentProfileDefinitionConfigView.as_view(), {'pk': 0}, name='profiles-create'),
    path('profiles/<int:pk>/', AgentProfileDefinitionConfigView.as_view(), name='profiles-config'),
    re_path(
        r'^profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        AgentProfileDefinitionBulkDeleteConfirmView.as_view(),
        name='profiles-delete_confirm',
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
    path(
        '<int:agent_id>/assigned-profiles/<int:pk>/edit/',
        AgentAssignedProfileEditView.as_view(),
        name='assigned-profiles-edit',
    ),
    path(
        '<int:agent_id>/assigned-profiles/<int:pk>/force-update/',
        AgentAssignedProfileForceUpdateView.as_view(),
        name='assigned-profiles-force-update',
    ),
    re_path(
        r'^(?P<agent_id>[0-9]+)/assigned-profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        AgentAssignedProfileDeleteView.as_view(),
        name='assigned-profiles-delete_confirm',
    ),
]
