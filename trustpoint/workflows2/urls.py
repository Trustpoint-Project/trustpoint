"""URL routes for the Workflow 2 app."""

from django.urls import path

from workflows2.views.approvals import (
    Workflow2ApprovalDetailView,
    Workflow2ApprovalListView,
    Workflow2ApprovalResolveView,
)
from workflows2.views.context_catalog import ContextCatalogView
from workflows2.views.definitions import (
    Workflow2DefinitionCreateView,
    Workflow2DefinitionEditView,
    Workflow2DefinitionListView,
)
from workflows2.views.dev import Workflow2DevView
from workflows2.views.graph_api import (
    Workflow2DefinitionGraphView,
)
from workflows2.views.graph_from_yaml_api import Workflow2GraphFromYamlView
from workflows2.views.instances import (
    Workflow2InstanceCancelView,
    Workflow2InstanceDetailView,
    Workflow2InstanceResumeView,
    Workflow2InstanceRunInlineView,
)
from workflows2.views.runs import (
    Workflow2RunCancelView,
    Workflow2RunDetailView,
    Workflow2RunListView,
    Workflow2RunRunInlineView,
)
from workflows2.views.triggers import Workflow2TriggerCatalogView

app_name = 'workflows2'

urlpatterns = [
    # Definitions
    path('definitions/', Workflow2DefinitionListView.as_view(), name='definitions_list'),
    path('definitions/new/', Workflow2DefinitionCreateView.as_view(), name='definitions_new'),
    path('definitions/<uuid:pk>/', Workflow2DefinitionEditView.as_view(), name='definitions_edit'),

    # API
    path('api/triggers/', Workflow2TriggerCatalogView.as_view(), name='api_triggers'),
    path('api/definitions/<uuid:pk>/graph/', Workflow2DefinitionGraphView.as_view(), name='api_definition_graph'),
    path('api/graph-from-yaml/', Workflow2GraphFromYamlView.as_view(), name='api_graph_from_yaml'),

    # Dev
    path('dev/', Workflow2DevView.as_view(), name='dev'),

    # Runs
    path('runs/', Workflow2RunListView.as_view(), name='runs-list'),
    path('runs/<uuid:run_id>/', Workflow2RunDetailView.as_view(), name='runs-detail'),
    path('runs/<uuid:run_id>/run-inline/', Workflow2RunRunInlineView.as_view(), name='runs-run-inline'),
    path('runs/<uuid:run_id>/cancel/', Workflow2RunCancelView.as_view(), name='runs-cancel'),

    # Instances
    path('instances/<uuid:instance_id>/', Workflow2InstanceDetailView.as_view(), name='instances-detail'),
    path('instances/<uuid:instance_id>/resume/', Workflow2InstanceResumeView.as_view(), name='instances-resume'),
    path(
        'instances/<uuid:instance_id>/run-inline/',
        Workflow2InstanceRunInlineView.as_view(),
        name='instances-run-inline',
    ),
    path('instances/<uuid:instance_id>/cancel/', Workflow2InstanceCancelView.as_view(), name='instances-cancel'),

    # Approvals
    path('approvals/', Workflow2ApprovalListView.as_view(), name='approvals-list'),
    path('approvals/<uuid:approval_id>/', Workflow2ApprovalDetailView.as_view(), name='approvals-detail'),
    path('approvals/<uuid:approval_id>/resolve/', Workflow2ApprovalResolveView.as_view(), name='approvals-resolve'),

    path('api/context-catalog/', ContextCatalogView.as_view(), name='context_catalog'),
]
