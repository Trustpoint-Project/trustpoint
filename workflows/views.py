from __future__ import annotations

from typing import Any
from uuid import UUID

from django.http import Http404, HttpRequest, JsonResponse
from django.views.generic import ListView, View

from workflows.models import AuditLog, WorkflowInstance
from workflows.services.orchestrator import advance_instance


class PendingApprovalsView(ListView[WorkflowInstance]):
    """List all workflow instances awaiting human approval."""
    model = WorkflowInstance
    template_name = 'workflows/pending_list.html'
    context_object_name = 'instances'

    def get_queryset(self) -> Any:
        return WorkflowInstance.objects.filter(state=WorkflowInstance.STATE_AWAITING)


class SignalInstanceView(View):
    """API endpoint to signal (approve/reject) a workflow instance."""

    def post(self, request: HttpRequest, instance_id: UUID, *args: Any, **kwargs: Any) -> JsonResponse:
        try:
            instance = WorkflowInstance.objects.get(id=instance_id)
        except WorkflowInstance.DoesNotExist:
            raise Http404(f'No instance with id {instance_id}')

        action = request.POST.get('action')
        if action not in {'Approved', 'Rejected'}:
            return JsonResponse({'error': 'Invalid action'}, status=400)

        AuditLog.objects.create(
            instance=instance,
            actor=str(request.user),
            action=action,
        )
        advance_instance(instance, signal=action)

        return JsonResponse({'new_state': instance.state})
