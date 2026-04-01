"""Monitoring views for Workflow 2 runs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views import View

from request.cmp_transaction_state import CmpTransactionState
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Instance, Workflow2Job, Workflow2Run
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.views.presentation import (
    build_step_meta_from_ir,
    describe_event_context,
    describe_step,
    pretty_json,
    resolve_source_context,
    status_badge_class,
    summarize_source,
)

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


class Workflow2RunListView(LoginRequiredMixin, View):
    """List workflow runs with filtering and status summaries."""

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the paginated run list."""
        supported_statuses = [choice[0] for choice in Workflow2Run.STATUS_CHOICES]
        base_qs = (
            Workflow2Run.objects.filter(status__in=supported_statuses)
            .annotate(instance_count=Count('instances'))
            .order_by('-created_at')
        )

        status = request.GET.get('status')
        trigger_on = (request.GET.get('trigger_on') or '').strip()

        qs = base_qs
        if status:
            qs = qs.filter(status=status)
        if trigger_on:
            qs = qs.filter(trigger_on__icontains=trigger_on)

        paginator = Paginator(qs, 25)
        page_obj = paginator.get_page(request.GET.get('page'))
        run_rows = [
            {
                'run': run,
                'badge': status_badge_class(run.status),
                'source_summary': summarize_source(run.source_json),
                'has_instances': bool(run.instance_count),
            }
            for run in page_obj.object_list
        ]
        active_statuses = [
            Workflow2Run.STATUS_QUEUED,
            Workflow2Run.STATUS_RUNNING,
            Workflow2Run.STATUS_AWAITING,
            Workflow2Run.STATUS_PAUSED,
        ]
        completed_statuses = [
            Workflow2Run.STATUS_SUCCEEDED,
            Workflow2Run.STATUS_REJECTED,
            Workflow2Run.STATUS_FAILED,
            Workflow2Run.STATUS_CANCELLED,
            Workflow2Run.STATUS_STOPPED,
        ]

        return render(
            request,
            'workflows2/runs_list.html',
            {
                'page_obj': page_obj,
                'run_rows': run_rows,
                'status': status or '',
                'trigger_on': trigger_on,
                'summary_total': qs.count(),
                'summary_active': qs.filter(status__in=active_statuses).count(),
                'summary_awaiting': qs.filter(status=Workflow2Run.STATUS_AWAITING).count(),
                'summary_completed': qs.filter(status__in=completed_statuses).count(),
                'status_choices': list(Workflow2Run.STATUS_CHOICES),
            },
        )


class Workflow2RunDetailView(LoginRequiredMixin, View):
    """Show one workflow run with its instances and event context."""

    def get(self, request: HttpRequest, run_id: int) -> HttpResponse:
        """Render the detail page for one workflow run."""
        supported_statuses = [choice[0] for choice in Workflow2Run.STATUS_CHOICES]
        run = get_object_or_404(Workflow2Run.objects.filter(status__in=supported_statuses), id=run_id)
        instances = Workflow2Instance.objects.filter(run=run).select_related('definition').order_by('created_at')
        source_context = resolve_source_context(run.source_json)
        event_context = describe_event_context(run.event_json)

        instance_rows = [
            {
                'instance': inst,
                'badge': status_badge_class(inst.status),
                'current_step': describe_step(
                    inst.current_step,
                    build_step_meta_from_ir(inst.definition.ir_json if inst.definition_id else None),
                ),
            }
            for inst in instances
        ]
        status_counts: dict[str, int] = {}
        for inst in instances:
            status_counts[inst.get_status_display()] = status_counts.get(inst.get_status_display(), 0) + 1

        outcome_summary = [
            {'label': label, 'value': str(count), 'meta': ''}
            for label, count in status_counts.items()
        ]

        return render(
            request,
            'workflows2/run_detail.html',
            {
                'run': run,
                'instance_rows': instance_rows,
                'run_badge': status_badge_class(run.status),
                'source_summary': source_context['summary'],
                'source_context': source_context,
                'source_pretty': pretty_json(run.source_json),
                'event_pretty': pretty_json(run.event_json),
                'event_context': event_context,
                'outcome_summary': outcome_summary,
            },
        )


class Workflow2RunRunInlineView(LoginRequiredMixin, View):
    """Execute all runnable instances in a run inline."""

    def post(self, request: HttpRequest, run_id: int) -> HttpResponse:
        """Run all non-terminal instances in the selected run inline."""
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
            messages.success(request, _('Run executed inline (all runnable instances processed).'))
        except Exception as e:  # noqa: BLE001
            messages.error(
                request,
                _('Inline run failed: %(type)s: %(error)s')
                % {'type': type(e).__name__, 'error': e},
            )

        return redirect('workflows2:runs-detail', run_id=run.id)


class Workflow2RunCancelView(LoginRequiredMixin, View):
    """Cancel a workflow run and its queued/running jobs."""

    def post(self, request: HttpRequest, run_id: int) -> HttpResponse:
        """Cancel the selected run and all non-terminal instances."""
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
                locked_by='',
            )

            for inst in insts:
                if inst.status not in {
                    Workflow2Instance.STATUS_SUCCEEDED,
                    Workflow2Instance.STATUS_REJECTED,
                    Workflow2Instance.STATUS_FAILED,
                    Workflow2Instance.STATUS_STOPPED,
                }:
                    inst.status = Workflow2Instance.STATUS_CANCELLED
                    inst.current_step = ''
                    inst.save(update_fields=['status', 'current_step', 'updated_at'])

            run.status = Workflow2Run.STATUS_CANCELLED
            run.finalized = True
            run.save(update_fields=['status', 'finalized', 'updated_at'])
            CmpTransactionState.sync_from_workflow2_run(run=run)

        messages.success(request, _('Run cancelled.'))
        return redirect('workflows2:runs-detail', run_id=run.id)
