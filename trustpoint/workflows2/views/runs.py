# workflows2/views/runs.py
from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Instance, Workflow2Job, Workflow2Run
from workflows2.services.runtime import WorkflowRuntimeService


class Workflow2RunListView(LoginRequiredMixin, View):
    def get(self, request: HttpRequest) -> HttpResponse:
        qs = Workflow2Run.objects.all().order_by('-created_at')

        status = request.GET.get('status')
        trigger_on = request.GET.get('trigger_on')

        if status:
            qs = qs.filter(status=status)
        if trigger_on:
            qs = qs.filter(trigger_on=trigger_on)

        qs = qs.annotate(instance_count=Count('instances'))

        paginator = Paginator(qs, 25)
        page_obj = paginator.get_page(request.GET.get('page'))

        return render(
            request,
            'workflows2/runs_list.html',
            {
                'page_obj': page_obj,
                'status': status or '',
                'trigger_on': trigger_on or '',
                'status_choices': Workflow2Run.STATUS_CHOICES,
            },
        )


class Workflow2RunDetailView(LoginRequiredMixin, View):
    def get(self, request: HttpRequest, run_id: int) -> HttpResponse:
        run = get_object_or_404(Workflow2Run, id=run_id)
        instances = Workflow2Instance.objects.filter(run=run).select_related('definition').order_by('created_at')

        return render(
            request,
            'workflows2/run_detail.html',
            {
                'run': run,
                'instances': instances,
            },
        )


class Workflow2RunRunInlineView(LoginRequiredMixin, View):
    def post(self, request: HttpRequest, run_id: int) -> HttpResponse:
        run = get_object_or_404(Workflow2Run, id=run_id)

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        insts = list(Workflow2Instance.objects.filter(run=run).order_by('created_at'))

        try:
            for inst in insts:
                if inst.status in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_FAILED,
                    Workflow2Instance.STATUS_STOPPED,
                    Workflow2Instance.STATUS_CANCELLED,
                    Workflow2Instance.STATUS_AWAITING,
                }:
                    continue
                runtime.run_instance(inst)

            runtime.recompute_run_status(run)
            messages.success(request, 'Run executed inline (all runnable instances processed).')
        except Exception as e:  # noqa: BLE001
            messages.error(request, f'Inline run failed: {type(e).__name__}: {e}')

        return redirect('workflows2:runs-detail', run_id=run.id)


class Workflow2RunCancelView(LoginRequiredMixin, View):
    def post(self, request: HttpRequest, run_id: int) -> HttpResponse:
        run = get_object_or_404(Workflow2Run, id=run_id)

        with transaction.atomic():
            run = Workflow2Run.objects.select_for_update().get(id=run.id)
            insts = list(Workflow2Instance.objects.select_for_update().filter(run=run))

            Workflow2Job.objects.filter(
                instance__in=insts,
                status__in=[Workflow2Job.STATUS_QUEUED, Workflow2Job.STATUS_RUNNING],
            ).update(
                status=Workflow2Job.STATUS_CANCELLED,
                locked_until=None,
                locked_by=None,
            )

            for inst in insts:
                if inst.status not in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_FAILED,
                    Workflow2Instance.STATUS_STOPPED,
                }:
                    inst.status = Workflow2Instance.STATUS_CANCELLED
                    inst.current_step = None
                    inst.save(update_fields=['status', 'current_step', 'updated_at'])

            run.status = Workflow2Run.STATUS_CANCELLED
            run.finalized = True
            run.save(update_fields=['status', 'finalized', 'updated_at'])

        messages.success(request, 'Run cancelled.')
        return redirect('workflows2:runs-detail', run_id=run.id)
