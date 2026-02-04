from django.urls import path

from workflows2.views.definitions import (
    Workflow2DefinitionCreateView,
    Workflow2DefinitionEditView,
    Workflow2DefinitionListView,
)
from workflows2.views.dev import Workflow2DevView
from workflows2.views.graph import Workflow2DefinitionGraphView, Workflow2GraphView
from workflows2.views.triggers import Workflow2TriggerCatalogView

app_name = 'workflows2'

urlpatterns = [
    path('definitions/', Workflow2DefinitionListView.as_view(), name='definitions_list'),
    path('definitions/new/', Workflow2DefinitionCreateView.as_view(), name='definitions_new'),
    path('definitions/<uuid:pk>/', Workflow2DefinitionEditView.as_view(), name='definitions_edit'),

    path('api/triggers/', Workflow2TriggerCatalogView.as_view(), name='api_triggers'),
    path('api/definitions/<uuid:pk>/graph/', Workflow2DefinitionGraphView.as_view(), name='api_definition_graph'),

    path('definitions/<uuid:pk>/graph/', Workflow2GraphView.as_view(), name='graph'),


    path('dev/', Workflow2DevView.as_view(), name='dev'),
]
