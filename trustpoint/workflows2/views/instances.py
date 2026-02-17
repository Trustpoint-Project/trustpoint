# workflows2/views/instances.py
from __future__ import annotations

import json

from django.contrib import messages
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Instance, Workflow2Job, Workflow2StepRun
from workflows2.services.runtime import WorkflowRuntimeService


class Workflow2InstanceDetailView(View):
    def get(self, request: HttpRequest, instance_id) -> HttpResponse:
        inst = get_object_or_404(Workflow2Instance.objects.select_related('definition', 'run'), id=instance_id)
        step_runs = Workflow2StepRun.objects.filter(instance=inst).order_by('-run_index')[:200]
        approvals = Workflow2Approval.objects.filter(instance=inst).order_by('-created_at')[:50]

        return render(
            request,
            'workflows2/instance_detail.html',
            {
                'inst': inst,
                'step_runs': step_runs,
                'approvals': approvals,
                'event_pretty': json.dumps(inst.event_json, indent=2, sort_keys=True, ensure_ascii=False),
                'vars_pretty': json.dumps(inst.vars_json, indent=2, sort_keys=True, ensure_ascii=False),
            },
        )


class Workflow2InstanceRunInlineView(View):
    """Force-run an instance inline from the web UI.
    Use-case: worker died / starting up / debugging.
    """

    def post(self, request: HttpRequest, instance_id) -> HttpResponse:
        inst = get_object_or_404(Workflow2Instance.objects.select_related('definition', 'run'), id=instance_id)

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        try:
            runtime.run_instance(inst)
            messages.success(request, 'Instance executed inline.')
        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Inline run failed: {type(e).__name__}: {e}')

        return redirect('workflows2:instances-detail', instance_id=inst.id)


class Workflow2InstanceCancelView(View):
    """Cancel an instance and cancel all non-terminal jobs for it.
    """

    def post(self, request: HttpRequest, instance_id) -> HttpResponse:
        inst = get_object_or_404(Workflow2Instance.objects.select_related('run'), id=instance_id)

        with transaction.atomic():
            inst = Workflow2Instance.objects.select_for_update().get(id=inst.id)

            Workflow2Job.objects.filter(
                instance=inst,
                status__in=[Workflow2Job.STATUS_QUEUED, Workflow2Job.STATUS_RUNNING],
            ).update(
                status=Workflow2Job.STATUS_CANCELLED,
                locked_until=None,
                locked_by=None,
            )

            inst.status = Workflow2Instance.STATUS_CANCELLED
            inst.current_step = None
            inst.save(update_fields=['status', 'current_step', 'updated_at'])

            if inst.run_id:
                executor = WorkflowExecutor()
                runtime = WorkflowRuntimeService(executor=executor)
                runtime.recompute_run_status(inst.run)

        messages.success(request, 'Instance cancelled.')
        return redirect('workflows2:instances-detail', instance_id=inst.id)


class Workflow2InstanceResumeView(View):
    """Resume = enqueue a resume job.
    """

    def post(self, request: HttpRequest, instance_id) -> HttpResponse:
        inst = get_object_or_404(Workflow2Instance, id=instance_id)

        try:
            Workflow2Job.objects.create(
                instance=inst,
                kind=Workflow2Job.KIND_RESUME,
                status=Workflow2Job.STATUS_QUEUED,
            )
            messages.success(request, 'Instance resume job enqueued.')
        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Resume failed: {type(e).__name__}: {e}')

        return redirect('workflows2:instances-detail', instance_id=inst.id)
