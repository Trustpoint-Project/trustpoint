# Register your models here.
"""Django admin configuration for the PKI app."""
from django.contrib import admin

from workflows2.models import (
    Workflow2Approval,
    Workflow2Definition,
    Workflow2DefinitionUiState,
    Workflow2Instance,
    Workflow2Job,
    Workflow2Run,
    Workflow2StepRun,
    Workflow2WorkerHeartbeat,
)


class Workflow2DefinitionAdmin(admin.ModelAdmin[Workflow2Definition]):
    """Admin configuration for the WorkflowDefinitionModel."""


class Workflow2RunAdmin(admin.ModelAdmin[Workflow2Run]):
    """Admin configuration for the WorkflowInstanceModel."""

class Workflow2InstanceAdmin(admin.ModelAdmin[Workflow2Instance]):
    """Admin configuration for the WorkflowScopeModel."""


class Workflow2ApprovalAdmin(admin.ModelAdmin[Workflow2Approval]):
    """Admin configuration for the WorkflowScopeModel."""

class Workflow2StepRunAdmin(admin.ModelAdmin[Workflow2StepRun]):
    """Admin configuration for the WorkflowScopeModel."""

class Workflow2JobAdmin(admin.ModelAdmin[Workflow2Job]):
    """Admin configuration for the WorkflowScopeModel."""

class Workflow2WorkerHeartbeatAdmin(admin.ModelAdmin[Workflow2WorkerHeartbeat]):
    """Admin configuration for the WorkflowScopeModel."""

class Workflow2DefinitionUiStateAdmin(admin.ModelAdmin[Workflow2DefinitionUiState]):
    """Admin configuration for the WorkflowScopeModel."""


admin.site.register(Workflow2Definition, Workflow2DefinitionAdmin)
admin.site.register(Workflow2Run, Workflow2RunAdmin)
admin.site.register(Workflow2Instance, Workflow2InstanceAdmin)
admin.site.register(Workflow2Approval, Workflow2ApprovalAdmin)
admin.site.register(Workflow2StepRun, Workflow2StepRunAdmin)
admin.site.register(Workflow2Job, Workflow2JobAdmin)
admin.site.register(Workflow2WorkerHeartbeat, Workflow2WorkerHeartbeatAdmin)
admin.site.register(Workflow2DefinitionUiState, Workflow2DefinitionUiStateAdmin)
