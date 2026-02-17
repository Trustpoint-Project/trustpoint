# workflows2/views/approvals.py
from __future__ import annotations

import json

from django.contrib import messages
from django.core.paginator import Paginator
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Instance, Workflow2Job
from workflows2.services.runtime import WorkflowRuntimeService


class Workflow2ApprovalListView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        qs = Workflow2Approval.objects.select_related('instance').order_by('-created_at')

        status = request.GET.get('status')
        if status:
            qs = qs.filter(status=status)

        paginator = Paginator(qs, 25)
        page_obj = paginator.get_page(request.GET.get('page'))

        return render(
            request,
            'workflows2/approvals_list.html',
            {
                'page_obj': page_obj,
                'status': status or '',
                'status_choices': Workflow2Approval.STATUS_CHOICES,
            },
        )


class Workflow2ApprovalDetailView(View):
    def get(self, request: HttpRequest, approval_id) -> HttpResponse:
        approval = get_object_or_404(
            Workflow2Approval.objects.select_related('instance', 'instance__definition', 'instance__run'),
            id=approval_id,
        )
        inst = approval.instance

        return render(
            request,
            'workflows2/approval_detail.html',
            {
                'approval': approval,
                'inst': inst,
                'event_pretty': json.dumps(inst.event_json, indent=2, sort_keys=True, ensure_ascii=False),
                'vars_pretty': json.dumps(inst.vars_json, indent=2, sort_keys=True, ensure_ascii=False),
            },
        )


class Workflow2ApprovalResolveView(View):
    """Approve/Reject.
    - Resolves approval transactionally (locks approval + instance)
    - Then continues either by enqueuing a job or running inline.
      (For now: enqueue a run job - consistent with DB worker mode.
       If you want "continue inline" always, change the marked section.)
    """

    def post(self, request: HttpRequest, approval_id) -> HttpResponse:
        decision = (request.POST.get('decision') or '').strip().lower()
        if decision not in {'approved', 'rejected'}:
            messages.error(request, "Invalid decision. Must be 'approved' or 'rejected'.")
            return redirect('workflows2:approvals-detail', approval_id=approval_id)

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        try:
            with transaction.atomic():
                approval = Workflow2Approval.objects.select_for_update().select_related('instance').get(id=approval_id)

                # Resolve approval updates instance.current_step -> next step and sets instance RUNNING/current_step
                runtime.resolve_approval(approval=approval, decision=decision)

                inst = Workflow2Instance.objects.select_for_update().get(id=approval.instance_id)

                # Continue execution:
                # Option A (recommended for worker mode): enqueue next execution step
                Workflow2Job.objects.create(
                    instance=inst,
                    kind=Workflow2Job.KIND_RUN,
                    status=Workflow2Job.STATUS_QUEUED,
                )

            messages.success(request, f'Approval resolved: {decision}. Continued via job queue.')
        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Resolve failed: {type(e).__name__}: {e}')

        return redirect('workflows2:approvals-detail', approval_id=approval_id)
