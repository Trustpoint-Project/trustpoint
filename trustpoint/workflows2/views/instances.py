"""Monitoring views for Workflow 2 instances."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View

from management.models.workflows2 import WorkflowExecutionConfig
from trustpoint.page_context import PageContextMixin
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Instance, Workflow2Job, Workflow2StepRun
from workflows2.services.runtime import WorkflowRuntimeService
from workflows2.views.presentation import (
    compact_value,
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


SUMMARY_LIMIT = 6


def _json_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _display_execution_mode(mode: str) -> str:
    """Return the canonical execution-mode label shown in the UI."""
    return 'worker' if mode == WorkflowExecutionConfig.Mode.WORKER else mode


def _safe_str(x: Any) -> str:
    if x is None:
        return ''
    return str(x)


def _summarize_keys(prefix: str, values: dict[str, Any]) -> str:
    """Return a truncated summary of mapping keys for UI cards."""
    keys = list(values)
    summary = f'{prefix}: ' + ', '.join(keys[:SUMMARY_LIMIT])
    if len(keys) > SUMMARY_LIMIT:
        summary += ' …'
    return summary


def _summarize_step(step_type: str, step: dict[str, Any], params: dict[str, Any]) -> str:
    """Return a compact summary string for one step."""
    if step_type in {'compute', 'set'}:
        mapping_key = 'set' if step_type == 'compute' else 'vars'
        return _summarize_keys(mapping_key, _json_object(params.get(mapping_key)))

    if step_type == 'logic':
        cases_value = params.get('cases')
        cases = cases_value if isinstance(cases_value, list) else []
        return f'cases={len(cases)} default={params.get("default")}'

    if step_type == 'webhook':
        method = _safe_str(params.get('method') or step.get('method') or '')
        url = _safe_str(params.get('url') or step.get('url') or '')
        return f'{method} {url}'.strip()
    if step_type == 'email':
        return f'to={params.get("to") or step.get("to")} subject={params.get("subject") or step.get("subject")}'
    if step_type == 'approval':
        timeout = params.get('timeout_seconds') or step.get('timeout_seconds')
        return f'{timeout}s timeout' if timeout else ''
    return ''


def _get_step_meta(inst: Workflow2Instance) -> dict[str, dict[str, Any]]:
    """Build a dict step_id -> meta derived from IR.

    We try multiple locations because compiler layout may evolve.
    """
    meta: dict[str, dict[str, Any]] = {}

    ir = _json_object(inst.definition.ir_json)
    wf = _json_object(ir.get('workflow'))
    steps_map = _json_object(wf.get('steps'))

    for step_id, step in steps_map.items():
        if not isinstance(step, dict):
            continue

        step_type = _safe_str(step.get('type') or '')
        params = _json_object(step.get('params'))

        # Title/description could be top-level or embedded
        title = (
            step.get('title')
            or params.get('title')
            or params.get('name')
            or ''
        )
        description = (
            step.get('description')
            or params.get('description')
            or ''
        )

        summary = ''
        try:
            summary = _summarize_step(step_type, step, params)
        except (TypeError, ValueError, AttributeError):
            summary = ''

        meta[str(step_id)] = {
            'id': str(step_id),
            'type': step_type,
            'title': _safe_str(title),
            'description': _safe_str(description),
            'summary': _safe_str(summary),
            'params': params,
        }

    return meta


class Workflow2InstanceDetailView(PageContextMixin, LoginRequiredMixin, View):
    """Show one workflow instance with step history, jobs, and approvals."""

    page_category = 'workflows2'
    page_name = 'runs-list'

    def get(self, request: HttpRequest, instance_id: UUID) -> HttpResponse:
        """Render the detail page for one workflow instance."""
        inst = get_object_or_404(Workflow2Instance.objects.select_related('definition', 'run'), id=instance_id)

        # Timeline reads better in ascending order
        step_runs = list(Workflow2StepRun.objects.filter(instance=inst).order_by('run_index')[:500])
        approvals = list(Workflow2Approval.objects.filter(instance=inst).order_by('-created_at')[:50])
        jobs = list(Workflow2Job.objects.filter(instance=inst).order_by('-created_at')[:50])

        step_meta = _get_step_meta(inst)
        current_step = describe_step(inst.current_step, step_meta)
        event_source = _json_object(inst.event_json).get('source')
        run = inst.run if inst.run_id else None
        source_context = resolve_source_context(run.source_json if run is not None else event_source)
        event_context = describe_event_context(inst.event_json)
        vars_summary = summarize_named_values(inst.vars_json)
        latest_step_run = step_runs[-1] if step_runs else None
        pending_approvals = [
            approval for approval in approvals if approval.status == Workflow2Approval.STATUS_PENDING
        ]
        resolved_approvals = [
            approval for approval in approvals if approval.status != Workflow2Approval.STATUS_PENDING
        ]
        latest_failed_step_run = next(
            (step_run for step_run in reversed(step_runs) if step_run.status == 'failed' or step_run.error),
            None,
        )
        latest_failed_job = next((job for job in jobs if job.last_error), None)

        # Render-ready list of "step run items"
        step_run_items: list[dict[str, Any]] = []
        for r in step_runs:
            m = step_meta.get(r.step_id) or {}
            params = _json_object(m.get('params'))

            step_run_items.append(
                {
                    'r': r,
                    'meta': m,
                    'badge': status_badge_class(r.status),
                    'vars_delta_pretty': pretty_json(r.vars_delta) if r.vars_delta is not None else '',
                    'output_pretty': pretty_json(r.output) if r.output is not None else '',
                    'params_pretty': pretty_json(params) if params else '',
                    'output_summary': compact_value(r.output),
                    'vars_delta_summary': compact_value(r.vars_delta),
                    'has_details': bool(r.error or r.output or r.vars_delta or params or m.get('description')),
                }
            )

        # Config for UI hint
        cfg = WorkflowExecutionConfig.load()
        cfg_mode = _display_execution_mode(str(cfg.mode).lower())

        return render(
            request,
            'workflows2/instance_detail.html',
            {
                'inst': inst,
                **self.get_context_data(),
                'approvals': approvals,
                'jobs': jobs,
                'step_run_items': step_run_items,
                'step_meta': step_meta,
                'current_step': current_step,
                'latest_step_run': latest_step_run,
                'pending_approvals': pending_approvals,
                'resolved_approvals': resolved_approvals,
                'latest_failed_step_run': latest_failed_step_run,
                'latest_failed_job': latest_failed_job,
                'source_context': source_context,
                'event_context': event_context,
                'vars_summary': vars_summary,
                'event_pretty': pretty_json(inst.event_json),
                'vars_pretty': pretty_json(inst.vars_json),
                'inst_badge': status_badge_class(inst.status),
                'cfg_mode': cfg_mode,
            },
        )


class Workflow2InstanceRunInlineView(LoginRequiredMixin, View):
    """Force-run inline. If FAILED, this is 'retry from current_step'."""

    def post(self, request: HttpRequest, instance_id: UUID) -> HttpResponse:
        """Execute the instance inline, resetting failed instances first."""
        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        try:
            with transaction.atomic():
                inst = Workflow2Instance.objects.select_for_update().get(id=instance_id)
                if inst.status == Workflow2Instance.STATUS_FAILED:
                    inst.status = Workflow2Instance.STATUS_QUEUED
                    inst.save(update_fields=['status', 'updated_at'])

            inst = Workflow2Instance.objects.get(id=instance_id)
            runtime.run_instance(inst)
            messages.success(request, _('Instance executed inline.'))
        except Exception as e:  # noqa: BLE001
            messages.error(
                request,
                _('Inline run failed: %(type)s: %(error)s')
                % {'type': type(e).__name__, 'error': e},
            )

        return redirect('workflows2:instances-detail', instance_id=instance_id)


class Workflow2InstanceCancelView(LoginRequiredMixin, View):
    """Cancel a workflow instance and its queued/running jobs."""

    def post(self, request: HttpRequest, instance_id: UUID) -> HttpResponse:
        """Cancel the selected instance."""
        inst = get_object_or_404(Workflow2Instance.objects.select_related('run'), id=instance_id)

        with transaction.atomic():
            inst = Workflow2Instance.objects.select_for_update().get(id=inst.id)

            Workflow2Job.objects.filter(
                instance=inst,
                status__in=[Workflow2Job.STATUS_QUEUED, Workflow2Job.STATUS_RUNNING],
            ).update(
                status=Workflow2Job.STATUS_CANCELLED,
                locked_until=None,
                locked_by='',
            )

            inst.status = Workflow2Instance.STATUS_CANCELLED
            inst.current_step = ''
            inst.save(update_fields=['status', 'current_step', 'updated_at'])

            if inst.run_id:
                executor = WorkflowExecutor()
                runtime = WorkflowRuntimeService(executor=executor)
                runtime.recompute_run_status(inst.run)

        messages.success(request, _('Instance cancelled.'))
        return redirect('workflows2:instances-detail', instance_id=inst.id)


class Workflow2InstanceResumeView(LoginRequiredMixin, View):
    """Retry failed step by re-queueing (and inline-executing if config is inline)."""

    def post(self, request: HttpRequest, instance_id: UUID) -> HttpResponse:
        """Resume a failed or paused instance by queueing another run."""
        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        try:
            with transaction.atomic():
                inst = Workflow2Instance.objects.select_for_update().get(id=instance_id)

                if inst.status not in {Workflow2Instance.STATUS_FAILED, Workflow2Instance.STATUS_PAUSED}:
                    messages.info(request, _('Instance is not failed/paused; nothing to retry.'))
                    return redirect('workflows2:instances-detail', instance_id=instance_id)

                inst.status = Workflow2Instance.STATUS_QUEUED
                inst.save(update_fields=['status', 'updated_at'])

                Workflow2Job.get_or_create_active(
                    instance=inst,
                    kind=Workflow2Job.KIND_RUN,
                    run_after=timezone.now(),
                )

            cfg = WorkflowExecutionConfig.load()
            if str(cfg.mode).lower() == WorkflowExecutionConfig.Mode.INLINE:
                inst = Workflow2Instance.objects.get(id=instance_id)
                runtime.run_instance(inst)
                messages.success(request, _('Retry executed inline.'))
            else:
                messages.success(request, _('Retry job enqueued.'))

        except Exception as e:  # noqa: BLE001
            messages.error(
                request,
                _('Retry failed: %(type)s: %(error)s')
                % {'type': type(e).__name__, 'error': e},
            )

        return redirect('workflows2:instances-detail', instance_id=instance_id)
