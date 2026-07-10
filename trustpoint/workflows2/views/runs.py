"""Monitoring views for Workflow 2 runs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q, TextField
from django.db.models.functions import Cast
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext as _
from django.views import View

from management.models.workflows2 import WorkflowExecutionConfig
from request.cmp_transaction_state import CmpTransactionState
from trustpoint.page_context import PageContextMixin
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Instance, Workflow2Job, Workflow2Run
from workflows2.services.dispatch import WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.services.transitions import (
    WorkflowInstanceTransitionService,
    WorkflowRunTransitionService,
    save_instance_status,
)
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


class Workflow2RunListView(PageContextMixin, LoginRequiredMixin, View):
    """List workflow runs with filtering and status summaries."""

    page_category = 'workflows2'
    page_name = 'runs-list'
    SORT_OPTIONS: ClassVar[dict[str, str]] = {
        'created': '-created_at',
        'created_asc': 'created_at',
        'updated': '-updated_at',
        'updated_asc': 'updated_at',
        'trigger': 'trigger_on',
        'trigger_desc': '-trigger_on',
        'status': 'status',
        'status_desc': '-status',
    }
    IDEMPOTENCY_FILTERS: ClassVar[set[str]] = {'locked', 'released', 'manual'}

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the paginated run list."""
        supported_statuses = [choice[0] for choice in Workflow2Run.STATUS_CHOICES]
        supported_status_set = set(supported_statuses)
        base_qs = (
            Workflow2Run.objects.filter(status__in=supported_statuses)
            .annotate(
                instance_count=Count('instances', distinct=True),
                event_text=Cast('event_json', output_field=TextField()),
                source_text=Cast('source_json', output_field=TextField()),
                run_id_text=Cast('id', output_field=TextField()),
            )
        )

        filters = self._read_filters(request, supported_status_set)
        sort = request.GET.get('sort') or 'created'

        qs = self._apply_filters(base_qs, filters)
        qs = qs.order_by(self.SORT_OPTIONS.get(sort, '-created_at'))
        query_without_sort = request.GET.copy()
        query_without_sort.pop('sort', None)
        query_without_sort.pop('page', None)
        query_without_sort.pop('finalized', None)

        trigger_choices = list(
            base_qs.order_by('trigger_on').values_list('trigger_on', flat=True).distinct()
        )

        paginator = Paginator(qs, 25)
        page_obj = paginator.get_page(request.GET.get('page'))
        run_rows = [
            {
                'run': run,
                'badge': status_badge_class(run.status),
                'source_summary': summarize_source(run.source_json),
                'has_instances': bool(run.instance_count),
                'idempotency_label': self._idempotency_label(run),
                'idempotency_badge': self._idempotency_badge(run),
            }
            for run in page_obj.object_list
        ]
        active_statuses = [
            *WorkflowRunTransitionService.ACTIVE_STATUSES,
            *WorkflowRunTransitionService.BLOCKED_STATUSES,
        ]
        completed_statuses = list(WorkflowRunTransitionService.TERMINAL_STATUSES)

        return render(
            request,
            'workflows2/runs_list.html',
            {
                'page_obj': page_obj,
                **self.get_context_data(),
                'run_rows': run_rows,
                'query': filters['query'],
                'status': filters['status'],
                'selected_triggers': filters['trigger_values'],
                'idempotency': filters['idempotency'],
                'trigger_choices': trigger_choices,
                'sort': sort,
                'query_without_sort': query_without_sort.urlencode(),
                'summary_total': qs.count(),
                'summary_active': qs.filter(status__in=active_statuses).count(),
                'summary_awaiting': qs.filter(status=Workflow2Run.STATUS_AWAITING).count(),
                'summary_completed': qs.filter(status__in=completed_statuses).count(),
                'status_choices': list(Workflow2Run.STATUS_CHOICES),
            },
        )

    def _read_filters(self, request: HttpRequest, supported_statuses: set[str]) -> dict[str, Any]:
        status = request.GET.get('status') or ''
        idempotency = request.GET.get('idempotency') or ''
        return {
            'query': (request.GET.get('q') or '').strip(),
            'status': status if status in supported_statuses else '',
            'trigger_values': [
                value.strip() for value in request.GET.getlist('trigger_on') if value.strip()
            ],
            'idempotency': idempotency if idempotency in self.IDEMPOTENCY_FILTERS else '',
        }

    def _apply_filters(self, qs: Any, filters: dict[str, Any]) -> Any:
        query = filters['query']
        if query:
            qs = self._apply_search(qs, query)
        if filters['status']:
            qs = qs.filter(status=filters['status'])
        if filters['trigger_values']:
            qs = qs.filter(trigger_on__in=filters['trigger_values'])

        idempotency = filters['idempotency']
        if idempotency == 'locked':
            qs = qs.exclude(idempotency_key='')
        elif idempotency == 'released':
            qs = qs.exclude(idempotency_released_at__isnull=True)
        elif idempotency == 'manual':
            qs = qs.filter(idempotency_release_mode='manual')
        return qs

    @staticmethod
    def _apply_search(qs: Any, query: str) -> Any:
        return qs.filter(
            Q(run_id_text__icontains=query)
            | Q(trigger_on__icontains=query)
            | Q(status__icontains=query)
            | Q(idempotency_key__icontains=query)
            | Q(idempotency_released_key__icontains=query)
            | Q(idempotency_released_by__icontains=query)
            | Q(idempotency_release_reason__icontains=query)
            | Q(event_text__icontains=query)
            | Q(source_text__icontains=query)
            | Q(instances__definition__name__icontains=query)
            | Q(instances__current_step__icontains=query)
            | Q(instances__status__icontains=query)
        ).distinct()

    @staticmethod
    def _idempotency_label(run: Workflow2Run) -> str:
        if run.idempotency_key:
            return _('Locked')
        if run.idempotency_release_mode == 'manual':
            return _('Released manually')
        if run.idempotency_released_at:
            return _('Released')
        return _('None')

    @staticmethod
    def _idempotency_badge(run: Workflow2Run) -> str:
        if run.idempotency_key:
            return 'text-bg-warning'
        if run.idempotency_release_mode == 'manual':
            return 'text-bg-info'
        if run.idempotency_released_at:
            return 'text-bg-secondary'
        return 'text-bg-light text-dark'


class Workflow2RunDetailView(PageContextMixin, LoginRequiredMixin, View):
    """Show one workflow run with its instances and event context."""

    page_category = 'workflows2'
    page_name = 'runs-list'

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
            status_counts[inst.status] = status_counts.get(inst.status, 0) + 1

        pending_approval_count = Workflow2Approval.objects.filter(
            instance__run=run,
            status=Workflow2Approval.STATUS_PENDING,
        ).count()
        terminal_instance_statuses = {
            *WorkflowInstanceTransitionService.TERMINAL_STATUSES,
        }
        inline_skipped_statuses = terminal_instance_statuses | {
            Workflow2Instance.STATUS_AWAITING,
            Workflow2Instance.STATUS_PAUSED,
            Workflow2Instance.STATUS_ERROR,
        }
        cfg = WorkflowExecutionConfig.load()
        can_run_inline = (
            str(cfg.mode).lower() != WorkflowExecutionConfig.Mode.INLINE
            and any(inst.status not in inline_skipped_statuses for inst in instances)
        )
        can_cancel = run.status in {
            Workflow2Run.STATUS_QUEUED,
            Workflow2Run.STATUS_RUNNING,
            Workflow2Run.STATUS_AWAITING,
            Workflow2Run.STATUS_PAUSED,
            Workflow2Run.STATUS_ERROR,
        }
        can_release_idempotency = bool(
            run.idempotency_key
            and run.status in WorkflowRunTransitionService.TERMINAL_STATUSES
        )

        return render(
            request,
            'workflows2/run_detail.html',
            {
                'run': run,
                **self.get_context_data(),
                'instance_rows': instance_rows,
                'run_badge': status_badge_class(run.status),
                'source_summary': source_context['summary'],
                'source_context': source_context,
                'source_pretty': pretty_json(run.source_json),
                'event_pretty': pretty_json(run.event_json),
                'event_context': event_context,
                'instance_total': len(instance_rows),
                'awaiting_instance_count': status_counts.get(Workflow2Instance.STATUS_AWAITING, 0),
                'error_instance_count': status_counts.get(Workflow2Instance.STATUS_ERROR, 0),
                'timed_out_instance_count': status_counts.get(Workflow2Instance.STATUS_TIMED_OUT, 0),
                'rejected_instance_count': status_counts.get(Workflow2Instance.STATUS_REJECTED, 0),
                'approved_instance_count': status_counts.get(Workflow2Instance.STATUS_APPROVED, 0),
                'finished_instance_count': status_counts.get(Workflow2Instance.STATUS_FINISHED, 0),
                'pending_approval_count': pending_approval_count,
                'can_run_inline': can_run_inline,
                'can_cancel': can_cancel,
                'can_release_idempotency': can_release_idempotency,
            },
        )


class Workflow2RunReleaseIdempotencyView(LoginRequiredMixin, View):
    """Allow the same request details to create a fresh workflow run."""

    def post(self, request: HttpRequest, run_id: int) -> HttpResponse:
        """Release the selected run's idempotency key."""
        released = WorkflowDispatchService.release_run_idempotency(
            run_id=run_id,
            actor=request.user,
            reason='Operator allowed the same request to trigger a new workflow run.',
            mode='manual',
        )
        if released:
            messages.success(request, _('Same request details can now trigger a new workflow run.'))
        else:
            messages.info(request, _('This run cannot be enabled for another identical request.'))
        return redirect('workflows2:runs-detail', run_id=run_id)


class Workflow2RunRunInlineView(LoginRequiredMixin, View):
    """Execute all runnable instances in a run inline."""

    def post(self, request: HttpRequest, run_id: int) -> HttpResponse:
        """Run all non-terminal instances in the selected run inline."""
        run = get_object_or_404(Workflow2Run, id=run_id)
        cfg = WorkflowExecutionConfig.load()
        if str(cfg.mode).lower() == WorkflowExecutionConfig.Mode.INLINE:
            messages.info(request, _('Inline execution is already handled by the workflow execution mode.'))
            return redirect('workflows2:runs-detail', run_id=run.id)

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        insts = list(Workflow2Instance.objects.filter(run=run).order_by('created_at'))

        try:
            for inst in insts:
                if inst.status in {
                    *WorkflowInstanceTransitionService.TERMINAL_STATUSES,
                    Workflow2Instance.STATUS_AWAITING,
                    Workflow2Instance.STATUS_PAUSED,
                    Workflow2Instance.STATUS_ERROR,
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
                    *WorkflowInstanceTransitionService.TERMINAL_STATUSES,
                }:
                    WorkflowInstanceTransitionService.mark_cancelled(inst)
                    save_instance_status(inst)

            run.status = Workflow2Run.STATUS_CANCELLED
            run.finalized = True
            run.save(update_fields=['status', 'finalized', 'updated_at'])
            CmpTransactionState.sync_from_workflow2_run(run=run)

        messages.success(request, _('Run cancelled.'))
        return redirect('workflows2:runs-detail', run_id=run.id)
