# Register your models here.
"""Django admin configuration for the PKI app."""
from django.contrib import admin

from workflows.models import DeviceRequest, EnrollmentRequest, WorkflowDefinition, WorkflowInstance, WorkflowScope, WorkflowStepRun


class WorkflowDefinitionAdmin(admin.ModelAdmin[WorkflowDefinition]):
    """Admin configuration for the WorkflowDefinitionModel."""


class WorkflowInstanceAdmin(admin.ModelAdmin[WorkflowInstance]):
    """Admin configuration for the WorkflowInstanceModel."""

class WorkflowScopeAdmin(admin.ModelAdmin[WorkflowScope]):
    """Admin configuration for the WorkflowScopeModel."""


class EnrollmentRequestAdmin(admin.ModelAdmin[EnrollmentRequest]):
    """Admin configuration for the WorkflowScopeModel."""

class DeviceRequestAdmin(admin.ModelAdmin[DeviceRequest]):
    """Admin configuration for the WorkflowScopeModel."""

class WorkflowStepRunadmin(admin.ModelAdmin[WorkflowStepRun]):
    """Admin configuration for the WorkflowScopeModel."""


admin.site.register(WorkflowDefinition, WorkflowDefinitionAdmin)
admin.site.register(WorkflowInstance, WorkflowInstanceAdmin)
admin.site.register(WorkflowScope, WorkflowScopeAdmin)
admin.site.register(EnrollmentRequest, EnrollmentRequestAdmin)
admin.site.register(DeviceRequest, DeviceRequestAdmin)
admin.site.register(WorkflowStepRun, WorkflowStepRunadmin)
