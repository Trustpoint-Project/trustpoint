# workflows2/views/instances.py
from __future__ import annotations

import json
from typing import Any

from django.contrib import messages
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from management.models import WorkflowExecutionConfig
from workflows2.engine.executor import WorkflowExecutor
from workflows2.models import Workflow2Approval, Workflow2Instance, Workflow2Job, Workflow2StepRun
from workflows2.services.runtime import WorkflowRuntimeService


def _pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)


def _status_badge_class(status: str | None) -> str:
    s = (status or "").strip().lower()
    if s in {"ok", "success", "succeeded", "done", "completed"}:
        return "text-bg-success"
    if s in {"failed", "error"}:
        return "text-bg-danger"
    if s in {"awaiting", "paused"}:
        return "text-bg-warning"
    if s in {"running"}:
        return "text-bg-primary"
    if s in {"queued"}:
        return "text-bg-secondary"
    if s in {"cancelled", "canceled"}:
        return "text-bg-dark"
    if s in {"rejected"}:
        return "text-bg-danger"
    if s in {"stopped"}:
        return "text-bg-info"
    return "text-bg-secondary"


def _safe_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x)


def _get_step_meta(inst: Workflow2Instance) -> dict[str, dict[str, Any]]:
    """
    Build a dict step_id -> meta derived from IR.
    We try multiple locations because compiler layout may evolve.
    """
    meta: dict[str, dict[str, Any]] = {}

    ir = inst.definition.ir_json if isinstance(inst.definition.ir_json, dict) else {}
    wf = ir.get("workflow") if isinstance(ir.get("workflow"), dict) else {}
    steps_map = wf.get("steps") if isinstance(wf.get("steps"), dict) else {}

    for step_id, step in steps_map.items():
        if not isinstance(step, dict):
            continue

        step_type = _safe_str(step.get("type") or "")
        params = step.get("params") if isinstance(step.get("params"), dict) else {}

        # Title/description could be top-level or embedded
        title = (
            step.get("title")
            or params.get("title")
            or params.get("name")
            or ""
        )
        description = (
            step.get("description")
            or params.get("description")
            or ""
        )

        # Build a compact "summary" for quick scanning
        summary = ""
        try:
            if step_type == "webhook":
                method = _safe_str(params.get("method") or step.get("method") or "")
                url = _safe_str(params.get("url") or step.get("url") or "")
                summary = f"{method} {url}".strip()
            elif step_type == "email":
                to = params.get("to") or step.get("to")
                subject = params.get("subject") or step.get("subject")
                summary = f"to={to} subject={subject}"
            elif step_type == "compute":
                set_map = params.get("set") if isinstance(params.get("set"), dict) else {}
                summary = "set: " + ", ".join(list(set_map.keys())[:6])
                if len(set_map.keys()) > 6:
                    summary += " …"
            elif step_type == "set":
                vars_map = params.get("vars") if isinstance(params.get("vars"), dict) else {}
                summary = "vars: " + ", ".join(list(vars_map.keys())[:6])
                if len(vars_map.keys()) > 6:
                    summary += " …"
            elif step_type == "logic":
                cases = params.get("cases") if isinstance(params.get("cases"), list) else []
                default = params.get("default")
                summary = f"cases={len(cases)} default={default}"
            elif step_type == "approval":
                timeout = params.get("timeout_seconds") or step.get("timeout_seconds")
                summary = f"timeout={timeout}s" if timeout else ""
        except Exception:
            summary = ""

        meta[str(step_id)] = {
            "id": str(step_id),
            "type": step_type,
            "title": _safe_str(title),
            "description": _safe_str(description),
            "summary": _safe_str(summary),
            "params": params,
        }

    return meta


class Workflow2InstanceDetailView(View):
    def get(self, request: HttpRequest, instance_id) -> HttpResponse:
        inst = get_object_or_404(Workflow2Instance.objects.select_related("definition", "run"), id=instance_id)

        # Timeline reads better in ascending order
        step_runs = list(Workflow2StepRun.objects.filter(instance=inst).order_by("run_index")[:500])
        approvals = list(Workflow2Approval.objects.filter(instance=inst).order_by("-created_at")[:50])
        jobs = list(Workflow2Job.objects.filter(instance=inst).order_by("-created_at")[:50])

        step_meta = _get_step_meta(inst)

        # Render-ready list of "step run items"
        step_run_items: list[dict[str, Any]] = []
        for r in step_runs:
            m = step_meta.get(r.step_id) or {}
            params = m.get("params") if isinstance(m.get("params"), dict) else {}

            step_run_items.append(
                {
                    "r": r,
                    "meta": m,
                    "badge": _status_badge_class(r.status),
                    "vars_delta_pretty": _pretty_json(r.vars_delta) if r.vars_delta is not None else "",
                    "output_pretty": _pretty_json(r.output) if r.output is not None else "",
                    "params_pretty": _pretty_json(params) if params else "",
                    "has_details": bool(r.error or r.output or r.vars_delta or params or m.get("description")),
                }
            )

        # Config for UI hint
        cfg = WorkflowExecutionConfig.load()
        cfg_mode = str(cfg.mode).lower()

        return render(
            request,
            "workflows2/instance_detail.html",
            {
                "inst": inst,
                "approvals": approvals,
                "jobs": jobs,
                "step_run_items": step_run_items,
                "step_meta": step_meta,
                "event_pretty": _pretty_json(inst.event_json),
                "vars_pretty": _pretty_json(inst.vars_json),
                "inst_badge": _status_badge_class(inst.status),
                "cfg_mode": cfg_mode,
            },
        )


class Workflow2InstanceRunInlineView(View):
    """Force-run inline. If FAILED, this is 'retry from current_step'."""

    def post(self, request: HttpRequest, instance_id) -> HttpResponse:
        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        try:
            with transaction.atomic():
                inst = Workflow2Instance.objects.select_for_update().get(id=instance_id)
                if inst.status == Workflow2Instance.STATUS_FAILED:
                    inst.status = Workflow2Instance.STATUS_QUEUED
                    inst.save(update_fields=["status", "updated_at"])

            inst = Workflow2Instance.objects.get(id=instance_id)
            runtime.run_instance(inst)
            messages.success(request, "Instance executed inline.")
        except Exception as e:  # noqa: BLE001
            messages.error(request, f"Inline run failed: {type(e).__name__}: {e}")

        return redirect("workflows2:instances-detail", instance_id=instance_id)


class Workflow2InstanceCancelView(View):
    def post(self, request: HttpRequest, instance_id) -> HttpResponse:
        inst = get_object_or_404(Workflow2Instance.objects.select_related("run"), id=instance_id)

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
            inst.save(update_fields=["status", "current_step", "updated_at"])

            if inst.run_id:
                executor = WorkflowExecutor()
                runtime = WorkflowRuntimeService(executor=executor)
                runtime.recompute_run_status(inst.run)

        messages.success(request, "Instance cancelled.")
        return redirect("workflows2:instances-detail", instance_id=inst.id)


class Workflow2InstanceResumeView(View):
    """Retry failed step by re-queueing (and inline-executing if config is inline)."""

    def post(self, request: HttpRequest, instance_id) -> HttpResponse:
        executor = WorkflowExecutor()
        runtime = WorkflowRuntimeService(executor=executor)

        try:
            with transaction.atomic():
                inst = Workflow2Instance.objects.select_for_update().get(id=instance_id)

                if inst.status not in {Workflow2Instance.STATUS_FAILED, Workflow2Instance.STATUS_PAUSED}:
                    messages.info(request, "Instance is not failed/paused; nothing to retry.")
                    return redirect("workflows2:instances-detail", instance_id=instance_id)

                inst.status = Workflow2Instance.STATUS_QUEUED
                inst.save(update_fields=["status", "updated_at"])

                Workflow2Job.objects.create(
                    instance=inst,
                    kind=Workflow2Job.KIND_RUN,
                    status=Workflow2Job.STATUS_QUEUED,
                    run_after=timezone.now(),
                )

            cfg = WorkflowExecutionConfig.load()
            if str(cfg.mode).lower() == WorkflowExecutionConfig.Mode.INLINE:
                inst = Workflow2Instance.objects.get(id=instance_id)
                runtime.run_instance(inst)
                messages.success(request, "Retry executed inline.")
            else:
                messages.success(request, "Retry job enqueued.")

        except Exception as e:  # noqa: BLE001
            messages.error(request, f"Retry failed: {type(e).__name__}: {e}")

        return redirect("workflows2:instances-detail", instance_id=instance_id)