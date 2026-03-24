# workflows2/views/approvals.py
from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db.models import Case, IntegerField, Value, When
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Instance
from workflows2.services.dispatch import WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.views.presentation import (
    describe_event_context,
    describe_step,
    pretty_json,
    resolve_source_context,
    status_badge_class,
    summarize_named_values,
)


class Workflow2ApprovalListView(LoginRequiredMixin, View):
    def get(self, request: HttpRequest) -> HttpResponse:
        base_qs = Workflow2Approval.objects.select_related(
            'instance',
            'instance__definition',
            'instance__run',
        ).annotate(
            pending_first=Case(
                When(status=Workflow2Approval.STATUS_PENDING, then=Value(0)),
                default=Value(1),
                output_field=IntegerField(),
            )
        ).order_by('pending_first', '-created_at')

        status = request.GET.get('status')
        qs = base_qs
        if status:
            qs = qs.filter(status=status)

        paginator = Paginator(qs, 25)
        page_obj = paginator.get_page(request.GET.get('page'))
        approval_rows = []
        for approval in page_obj.object_list:
            step_meta = _get_approval_step_meta(approval)
            approval_rows.append(
                {
                    'approval': approval,
                    'badge': status_badge_class(approval.status),
                    'step_meta': step_meta,
                    'instance_badge': status_badge_class(approval.instance.status if approval.instance else None),
                    'run_badge': status_badge_class(
                        approval.instance.run.status
                        if approval.instance and approval.instance.run_id
                        else None
                    ),
                    'can_resolve': approval.status == Workflow2Approval.STATUS_PENDING
                    and approval.instance
                    and approval.instance.status == Workflow2Instance.STATUS_AWAITING,
                }
            )

        return render(
            request,
            'workflows2/approvals_list.html',
            {
                'page_obj': page_obj,
                'approval_rows': approval_rows,
                'status': status or '',
                'status_choices': Workflow2Approval.STATUS_CHOICES,
                'summary_total': qs.count(),
                'summary_pending': qs.filter(status=Workflow2Approval.STATUS_PENDING).count(),
                'summary_resolved': qs.filter(
                    status__in=[
                        Workflow2Approval.STATUS_APPROVED,
                        Workflow2Approval.STATUS_REJECTED,
                    ]
                ).count(),
                'summary_expired': qs.filter(status=Workflow2Approval.STATUS_EXPIRED).count(),
            },
        )


class Workflow2ApprovalDetailView(LoginRequiredMixin, View):
    def get(self, request: HttpRequest, approval_id) -> HttpResponse:
        approval = get_object_or_404(
            Workflow2Approval.objects.select_related('instance', 'instance__definition', 'instance__run'),
            id=approval_id,
        )
        inst = approval.instance
        step_meta = _get_approval_step_meta(approval)
        step_display = describe_step(approval.step_id, {approval.step_id: {
            'id': approval.step_id,
            'title': str(step_meta.get('title') or approval.step_id),
            'type': 'approval',
            'description': '',
        }})
        event_source = inst.event_json.get('source') if isinstance(inst.event_json, dict) else None
        source_context = resolve_source_context(inst.run.source_json if inst.run_id else event_source)
        event_context = describe_event_context(inst.event_json)
        vars_summary = summarize_named_values(inst.vars_json)

        return render(
            request,
            'workflows2/approval_detail.html',
            {
                'approval': approval,
                'inst': inst,
                'step_meta': step_meta,
                'step_display': step_display,
                'source_context': source_context,
                'event_context': event_context,
                'vars_summary': vars_summary,
                'approval_badge': status_badge_class(approval.status),
                'instance_badge': status_badge_class(inst.status),
                'run_badge': status_badge_class(inst.run.status if inst.run_id else None),
                'can_resolve': approval.status == Workflow2Approval.STATUS_PENDING
                and inst.status == Workflow2Instance.STATUS_AWAITING,
                'event_pretty': pretty_json(inst.event_json),
                'vars_pretty': pretty_json(inst.vars_json),
            },
        )


class Workflow2ApprovalResolveView(LoginRequiredMixin, View):
    """Approve/Reject and continue with the normal dispatch execution policy."""

    def post(self, request: HttpRequest, approval_id) -> HttpResponse:
        decision = (request.POST.get('decision') or '').strip().lower()
        comment = (request.POST.get('comment') or '').strip()
        if decision not in {'approved', 'rejected'}:
            messages.error(request, "Invalid decision. Must be 'approved' or 'rejected'.")
            return redirect('workflows2:approvals-detail', approval_id=approval_id)

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)
        dispatch = WorkflowDispatchService(executor=executor)
        continue_inline = dispatch.runs_inline()

        try:
            with transaction.atomic():
                approval = Workflow2Approval.objects.select_for_update().select_related('instance').get(id=approval_id)

                # Resolve approval updates instance.current_step -> next step and sets instance RUNNING/current_step
                runtime.resolve_approval(
                    approval=approval,
                    decision=decision,
                    decided_by=request.user.get_username() or None,
                    comment=comment or None,
                )

                inst = Workflow2Instance.objects.select_for_update().get(id=approval.instance_id)

                if inst.status == Workflow2Instance.STATUS_RUNNING and inst.current_step:
                    dispatch.continue_instance(instance=inst)
                    if continue_inline:
                        success_message = f'Approval resolved: {decision}. Workflow continued inline.'
                    else:
                        success_message = f'Approval resolved: {decision}. Next workflow step queued.'
                elif inst.status == Workflow2Instance.STATUS_SUCCEEDED:
                    success_message = f'Approval resolved: {decision}. Workflow ended successfully.'
                elif inst.status == Workflow2Instance.STATUS_REJECTED:
                    success_message = f'Approval resolved: {decision}. Workflow ended rejected.'
                else:
                    success_message = f'Approval resolved: {decision}.'

            messages.success(request, success_message)
        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Resolve failed: {type(e).__name__}: {e}')

        return redirect('workflows2:approvals-detail', approval_id=approval_id)


def _get_approval_step_meta(approval: Workflow2Approval) -> dict[str, str | int | None]:
    instance = approval.instance
    definition = instance.definition if instance else None
    ir = definition.ir_json if definition and isinstance(definition.ir_json, dict) else {}
    workflow = ir.get('workflow') if isinstance(ir.get('workflow'), dict) else {}
    steps = workflow.get('steps') if isinstance(workflow.get('steps'), dict) else {}
    step = steps.get(approval.step_id) if isinstance(steps, dict) else None
    params = step.get('params') if isinstance(step, dict) and isinstance(step.get('params'), dict) else {}

    return {
        'title': (
            (step.get('title') if isinstance(step, dict) else None)
            or params.get('title')
            or approval.step_id
        ),
        'approved_outcome': (
            params.get('approved_outcome')
            or (step.get('approved_outcome') if isinstance(step, dict) else None)
        ),
        'rejected_outcome': (
            params.get('rejected_outcome')
            or (step.get('rejected_outcome') if isinstance(step, dict) else None)
        ),
        'timeout_seconds': (
            params.get('timeout_seconds')
            or (step.get('timeout_seconds') if isinstance(step, dict) else None)
        ),
    }
