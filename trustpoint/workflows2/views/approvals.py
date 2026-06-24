"""Approval queue and resolution views for Workflow 2."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View

from trustpoint.page_context import PageContextMixin
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Instance
from workflows2.services.dispatch import WorkflowDispatchService
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.views.presentation import (
    build_step_meta_from_ir,
    describe_event_context,
    describe_step,
    pretty_json,
    resolve_source_context,
    status_badge_class,
    summarize_named_values,
)

if TYPE_CHECKING:
    from uuid import UUID

    from django.http import HttpRequest, HttpResponse


def _json_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _expire_pending_approvals() -> None:
    now = timezone.now()
    approval_ids = list(Workflow2Approval.objects.filter(
        status=Workflow2Approval.STATUS_PENDING,
        expires_at__isnull=False,
        expires_at__lte=now,
    ).values_list('id', flat=True))
    if not approval_ids:
        return

    executor = WorkflowExecutor()
    runtime = WorkflowRuntimeService(executor=executor)
    dispatch = WorkflowDispatchService(executor=executor)
    for approval_id in approval_ids:
        with transaction.atomic():
            approval = (
                Workflow2Approval.objects.select_for_update()
                .select_related('instance', 'instance__run')
                .get(id=approval_id)
            )
            if approval.status != Workflow2Approval.STATUS_PENDING:
                continue

            approval.status = Workflow2Approval.STATUS_EXPIRED
            approval.decided_at = now
            approval.decided_by = ''
            approval.comment = ''
            approval.save(update_fields=['status', 'decided_at', 'decided_by', 'comment'])

            inst = approval.instance
            if inst.status == Workflow2Instance.STATUS_AWAITING and inst.current_step == approval.step_id:
                continued = runtime.record_approval_timeout_locked(inst=inst, approval=approval)
                if continued:
                    dispatch.continue_instance(instance=inst)


def _build_timeout_context(
    approval: Workflow2Approval,
    *,
    timeout_seconds: int | None,
) -> dict[str, object]:
    """Return render-friendly timeout information for one approval."""
    expires_at = approval.expires_at
    has_timeout = bool(timeout_seconds) or expires_at is not None
    is_expired = approval.status == Workflow2Approval.STATUS_EXPIRED

    return {
        'has_timeout': has_timeout,
        'timeout_seconds': timeout_seconds,
        'expires_at': expires_at,
        'is_expired': is_expired,
    }


class Workflow2WaitingListView(PageContextMixin, LoginRequiredMixin, View):
    """List workflow items waiting for user action."""

    page_category = 'workflows2'
    page_name = 'waiting-list'
    SORT_OPTIONS: ClassVar[set[str]] = {'created', 'created_asc'}

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the paginated queue of approvals, paused instances, and errors."""
        _expire_pending_approvals()
        approval_qs = Workflow2Approval.objects.select_related(
            'instance',
            'instance__definition',
            'instance__run',
        ).filter(
            status=Workflow2Approval.STATUS_PENDING,
            instance__status=Workflow2Instance.STATUS_AWAITING,
        )
        paused_qs = Workflow2Instance.objects.select_related('definition', 'run').filter(
            status=Workflow2Instance.STATUS_PAUSED,
        )
        errored_qs = Workflow2Instance.objects.select_related('definition', 'run').filter(
            status=Workflow2Instance.STATUS_ERROR,
        )

        kind = request.GET.get('kind') or ''
        sort = request.GET.get('sort') or 'created'
        if sort not in self.SORT_OPTIONS:
            sort = 'created'

        rows: list[dict[str, Any]] = []
        if kind in {'', 'approval'}:
            rows.extend(self._approval_rows(approval_qs))
        if kind in {'', 'paused'}:
            rows.extend(self._paused_rows(paused_qs))
        if kind in {'', 'error'}:
            rows.extend(self._error_rows(errored_qs))

        rows = self._sort_rows(rows, sort)

        paginator = Paginator(rows, 25)
        page_obj = paginator.get_page(request.GET.get('page'))

        return render(
            request,
            'workflows2/approvals_list.html',
            {
                'page_obj': page_obj,
                **self.get_context_data(),
                'waiting_rows': list(page_obj.object_list),
                'kind': kind,
                'sort': sort,
                'summary_total': len(rows),
                'summary_pending_approvals': approval_qs.count(),
                'summary_paused_instances': paused_qs.count(),
                'summary_error_instances': errored_qs.count(),
            },
        )

    @staticmethod
    def _approval_rows(approval_qs: Any) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for approval in approval_qs:
            step_meta = _get_approval_step_meta(approval)
            inst = approval.instance
            rows.append(
                {
                    'kind': 'approval',
                    'kind_label': _('Approval'),
                    'state_label': approval.get_status_display(),
                    'badge': status_badge_class(approval.status),
                    'title': step_meta['title'],
                    'step_id': approval.step_id,
                    'workflow': inst.definition if inst else None,
                    'instance': inst,
                    'run': inst.run if inst and inst.run_id else None,
                    'created_at': approval.created_at,
                    'sort_at': approval.created_at,
                    'expires_at': approval.expires_at,
                    'detail': _('Decision required'),
                    'open_url_name': 'workflows2:approvals-detail',
                    'open_url_arg': approval.id,
                    'open_label': _('Review'),
                }
            )
        return rows

    @staticmethod
    def _paused_rows(paused_qs: Any) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for inst in paused_qs:
            step_display = describe_step(
                inst.current_step,
                build_step_meta_from_ir(inst.definition.ir_json if inst.definition_id else None),
            )
            rows.append(
                {
                    'kind': 'paused',
                    'kind_label': _('Paused'),
                    'state_label': inst.get_status_display(),
                    'badge': status_badge_class(inst.status),
                    'title': step_display['title'] if step_display else _('Paused workflow'),
                    'step_id': inst.current_step,
                    'workflow': inst.definition,
                    'instance': inst,
                    'run': inst.run if inst.run_id else None,
                    'created_at': inst.updated_at,
                    'sort_at': inst.updated_at,
                    'expires_at': None,
                    'detail': inst.status_message or inst.status_reason or _('Resume required'),
                    'open_url_name': 'workflows2:instances-detail',
                    'open_url_arg': inst.id,
                    'open_label': _('Open'),
                    'can_resume': True,
                    'can_stop': True,
                }
            )
        return rows

    @staticmethod
    def _error_rows(errored_qs: Any) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for inst in errored_qs:
            step_display = describe_step(
                inst.current_step,
                build_step_meta_from_ir(inst.definition.ir_json if inst.definition_id else None),
            )
            rows.append(
                {
                    'kind': 'error',
                    'kind_label': _('Error'),
                    'state_label': inst.get_status_display(),
                    'badge': status_badge_class(inst.status),
                    'title': step_display['title'] if step_display else _('Errored workflow'),
                    'step_id': inst.current_step,
                    'workflow': inst.definition,
                    'instance': inst,
                    'run': inst.run if inst.run_id else None,
                    'created_at': inst.updated_at,
                    'sort_at': inst.updated_at,
                    'expires_at': None,
                    'detail': inst.status_message or inst.status_reason or _('Operator decision required'),
                    'open_url_name': 'workflows2:instances-detail',
                    'open_url_arg': inst.id,
                    'open_label': _('Open'),
                    'can_resume': True,
                    'can_stop': True,
                }
            )
        return rows

    @staticmethod
    def _sort_rows(rows: list[dict[str, Any]], sort: str) -> list[dict[str, Any]]:
        if sort == 'created_asc':
            return sorted(rows, key=lambda row: row['sort_at'])
        return sorted(rows, key=lambda row: row['sort_at'], reverse=True)


Workflow2ApprovalListView = Workflow2WaitingListView


class Workflow2ApprovalDetailView(PageContextMixin, LoginRequiredMixin, View):
    """Show a single approval request in context."""

    page_category = 'workflows2'
    page_name = 'waiting-list'

    def get(self, request: HttpRequest, approval_id: UUID) -> HttpResponse:
        """Render the detail page for one approval request."""
        _expire_pending_approvals()
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
        event_source = _json_object(inst.event_json).get('source')
        run = inst.run if inst.run_id else None
        source_context = resolve_source_context(run.source_json if run is not None else event_source)
        event_context = describe_event_context(inst.event_json)
        vars_summary = summarize_named_values(inst.vars_json)
        timeout_seconds_raw = step_meta.get('timeout_seconds')
        timeout_seconds = timeout_seconds_raw if isinstance(timeout_seconds_raw, int) else None
        timeout_context = _build_timeout_context(
            approval,
            timeout_seconds=timeout_seconds,
        )

        return render(
            request,
            'workflows2/approval_detail.html',
            {
                'approval': approval,
                **self.get_context_data(),
                'inst': inst,
                'step_meta': step_meta,
                'step_display': step_display,
                'source_context': source_context,
                'event_context': event_context,
                'vars_summary': vars_summary,
                'approval_badge': status_badge_class(approval.status),
                'instance_badge': status_badge_class(inst.status),
                'run_badge': status_badge_class(run.status if run is not None else None),
                'can_resolve': approval.status == Workflow2Approval.STATUS_PENDING
                and inst.status == Workflow2Instance.STATUS_AWAITING,
                'timeout_context': timeout_context,
                'event_pretty': pretty_json(inst.event_json),
                'vars_pretty': pretty_json(inst.vars_json),
            },
        )


class Workflow2ApprovalResolveView(LoginRequiredMixin, View):
    """Approve/Reject and continue with the normal dispatch execution policy."""

    def post(self, request: HttpRequest, approval_id: UUID) -> HttpResponse:
        """Resolve an approval and continue execution if the workflow can proceed."""
        decision = (request.POST.get('decision') or '').strip().lower()
        comment = (request.POST.get('comment') or '').strip()
        if decision not in {'approved', 'rejected'}:
            messages.error(request, _("Invalid decision. Must be 'approved' or 'rejected'."))
            return redirect('workflows2:approvals-detail', approval_id=approval_id)

        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)
        dispatch = WorkflowDispatchService(executor=executor)
        continue_inline = dispatch.runs_inline()

        try:
            with transaction.atomic():
                approval = Workflow2Approval.objects.select_for_update().select_related('instance').get(id=approval_id)

                # Resolve approval updates instance.current_step -> next step and sets instance RUNNING/current_step
                resolution = runtime.resolve_approval(
                    approval=approval,
                    decision=decision,
                    decided_by=request.user.get_username() or None,
                    comment=comment or None,
                )

                inst = Workflow2Instance.objects.select_for_update().get(id=approval.instance_id)

                if inst.status == Workflow2Instance.STATUS_RUNNING and inst.current_step:
                    dispatch.continue_instance(instance=inst)
                    if resolution.expired and continue_inline:
                        success_message = _('Approval expired. Timeout branch continued inline.')
                    elif resolution.expired:
                        success_message = _('Approval expired. Timeout branch queued.')
                    elif continue_inline:
                        success_message = _(
                            'Approval resolved: %(decision)s. Workflow continued inline.'
                        ) % {'decision': decision}
                    else:
                        success_message = _(
                            'Approval resolved: %(decision)s. Next workflow step queued.'
                        ) % {'decision': decision}
                elif inst.status == Workflow2Instance.STATUS_APPROVED:
                    success_message = _(
                        'Approval resolved: %(decision)s. Workflow ended approved.'
                    ) % {'decision': decision}
                elif inst.status == Workflow2Instance.STATUS_TIMED_OUT:
                    success_message = _(
                        'Approval expired before it could be resolved. Workflow timed out.'
                    )
                elif inst.status == Workflow2Instance.STATUS_REJECTED:
                    success_message = _(
                        'Approval resolved: %(decision)s. Workflow ended rejected.'
                    ) % {'decision': decision}
                else:
                    success_message = _('Approval resolved: %(decision)s.') % {'decision': decision}

            messages.success(request, success_message)
        except Exception as e:  # noqa: BLE001
            messages.error(
                request,
                _('Resolve failed: %(type)s: %(error)s')
                % {'type': type(e).__name__, 'error': e},
            )

        return redirect('workflows2:approvals-detail', approval_id=approval_id)


def _get_approval_step_meta(approval: Workflow2Approval) -> dict[str, str | int | None]:
    instance = approval.instance
    definition = instance.definition if instance else None
    ir = _json_object(definition.ir_json if definition else None)
    workflow = _json_object(ir.get('workflow'))
    steps = _json_object(workflow.get('steps'))
    step = _json_object(steps.get(approval.step_id))
    params = _json_object(step.get('params'))

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
        'timeout_outcome': (
            params.get('timeout_outcome')
            or (step.get('timeout_outcome') if isinstance(step, dict) else None)
        ),
        'timeout_seconds': (
            params.get('timeout_seconds')
            or (step.get('timeout_seconds') if isinstance(step, dict) else None)
        ),
    }
