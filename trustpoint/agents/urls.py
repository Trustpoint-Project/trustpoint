"""URL configuration for the agents application."""
from django.urls import include, path, re_path

from agents.web_views import (
    AgentManagedDeviceCreateView,
    AgentManagedDeviceDeleteView,
    AgentManagedDeviceTableView,
    AgentWorkflowDefinitionBulkDeleteConfirmView,
    AgentWorkflowDefinitionConfigView,
    AgentWorkflowDefinitionTableView,
)

app_name = 'agents'

urlpatterns = [
    path('agents/wbm/', include('agents.wbm.urls', namespace='agents_wbm')),
    path('profiles/', AgentWorkflowDefinitionTableView.as_view(), name='profiles'),
    path('profiles/<int:pk>/', AgentWorkflowDefinitionConfigView.as_view(), name='profiles-config'),
    re_path(
        r'^profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$',
        AgentWorkflowDefinitionBulkDeleteConfirmView.as_view(),
        name='profiles-delete_confirm',
    ),
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
]
