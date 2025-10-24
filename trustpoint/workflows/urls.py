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
    WizardPrefillView,
    WorkflowDefinitionDeleteView,
    WorkflowDefinitionExportView,
    WorkflowDefinitionImportView,
    WorkflowDefinitionListView,
    WorkflowDefinitionPublishView,
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
    path('api/wizard-prefill/', WizardPrefillView.as_view(), name='api_wizard_prefill'),

    # load one definition for “edit” in the wizard
    path('api/definitions/<uuid:pk>/', DefinitionDetailView.as_view(), name='definition_detail'),
    path('api/context-catalog/<uuid:instance_id>/', ContextCatalogView.as_view(), name='context_catalog'),

    # main UI
    path('', WorkflowDefinitionListView.as_view(), name='definition_list'),
    path('wizard/', WorkflowWizardView.as_view(), name='definition_wizard'),
    path('definitions/<uuid:pk>/publish/', WorkflowDefinitionPublishView.as_view(), name='definition_publish'),
    path('definitions/<uuid:pk>/export/', WorkflowDefinitionExportView.as_view(), name='definition_export'),
    path('definitions/import/', WorkflowDefinitionImportView.as_view(), name='definition_import'),

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
