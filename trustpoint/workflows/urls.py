"""URL configuration for the workflows app.

Defines API endpoints and UI views for managing workflows,
including scope pickers, workflow definitions, approvals,
and signaling workflow instances.
"""
from django.urls import path

from workflows.views import (
    CAListView,
    ContextCatalogView,
    DefinitionDetailView,
    DeviceListView,
    DomainListView,
    MailTemplateListView,
    PendingApprovalsView,
    SignalInstanceView,
    TriggerListView,
    WorkflowDefinitionDeleteView,
    WorkflowDefinitionListView,
    WorkflowInstanceDetailView,
    WorkflowWizardView,
)

app_name = 'workflows'

urlpatterns = [
    # scope pickers
    path('api/cas/', CAListView.as_view(), name='api_cas'),
    path('api/domains/', DomainListView.as_view(), name='api_domains'),
    path('api/devices/', DeviceListView.as_view(), name='api_devices'),
    path('api/triggers/', TriggerListView.as_view(), name='api_triggers'),
    path('api/mail-templates/', MailTemplateListView.as_view(), name='api_mail_templates'),

    # load one definition for “edit” in the wizard
    path('api/definitions/<uuid:pk>/', DefinitionDetailView.as_view(), name='definition_detail'),
    path('context-catalog/<uuid:instance_id>/', ContextCatalogView.as_view(), name='context_catalog'),

    # main UI
    path('', WorkflowDefinitionListView.as_view(), name='definition_list'),
    path('wizard/', WorkflowWizardView.as_view(), name='definition_wizard'),

    # delete workflow definition
    path(
        'definitions/<uuid:pk>/delete/',
        WorkflowDefinitionDeleteView.as_view(),
        name='definition_delete'
    ),

    # approval console
    path('pending/', PendingApprovalsView.as_view(), name='pending_list'),
    path('pending/<uuid:instance_id>/', WorkflowInstanceDetailView.as_view(), name='pending_detail'),
    path('instances/<uuid:instance_id>/signal/', SignalInstanceView.as_view(), name='signal'),
]
