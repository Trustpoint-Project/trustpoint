# Register your models here.
"""Django admin configuration for the PKI app."""
from django.contrib import admin

from workflows.models import EnrollmentRequest, WorkflowDefinition, WorkflowInstance, WorkflowScope


class WorkflowDefinitionAdmin(admin.ModelAdmin[WorkflowDefinition]):
    """Admin configuration for the WorkflowDefinitionModel."""


class WorkflowInstanceAdmin(admin.ModelAdmin[WorkflowInstance]):
    """Admin configuration for the WorkflowInstanceModel."""

class WorkflowScopeAdmin(admin.ModelAdmin[WorkflowScope]):
    """Admin configuration for the WorkflowScopeModel."""


class EnrollmentRequestAdmin(admin.ModelAdmin[EnrollmentRequest]):
    """Admin configuration for the WorkflowScopeModel."""


admin.site.register(WorkflowDefinition, WorkflowDefinitionAdmin)
admin.site.register(WorkflowInstance, WorkflowInstanceAdmin)
admin.site.register(WorkflowScope, WorkflowScopeAdmin)
admin.site.register(EnrollmentRequest, EnrollmentRequestAdmin)
