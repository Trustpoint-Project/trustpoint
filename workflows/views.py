from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from devices.models import DeviceModel
from django.db import IntegrityError
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    JsonResponse,
)
from django.shortcuts import render
from django.views import View
from django.views.generic import ListView
from pki.models import DomainModel, IssuingCaModel

from workflows.models import (
    AuditLog,
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowScope,
)
from workflows.services.certificate_request import advance_instance
from workflows.services.wizard import transform_to_definition_schema
from workflows.triggers import STEP_PARAM_DEFS, Triggers


class CAListView(View):
    """Return all issuing CAs as JSON."""
    def get(
        self,
        _request: HttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        data = [
            {'id': str(c.id), 'name': c.unique_name}
            for c in IssuingCaModel.objects.filter(is_active=True)
        ]
        return JsonResponse(data, safe=False)


class DomainListView(View):
    """Return all domains as JSON."""
    def get(
        self,
        _request: HttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        data = [
            {'id': str(d.id), 'name': d.unique_name}
            for d in DomainModel.objects.filter(is_active=True)
        ]
        return JsonResponse(data, safe=False)


class DeviceListView(View):
    """Return all devices as JSON."""
    def get(
        self,
        _request: HttpRequest,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        data = [
            {'id': str(d.id), 'name': d.common_name}
            for d in DeviceModel.objects.select_related('domain').all()
        ]
        return JsonResponse(data, safe=False)


class TriggerListView(View):
    """Return all Triggers as JSON."""
    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        out: dict[str, list[str]] = {}
        for proto in Triggers.protocols():
            out[proto] = Triggers.operations_for(proto)
        return JsonResponse(out)


class DefinitionDetailView(View):
    """Return JSON for a WorkflowDefinition (triggers, steps, scopes)."""
    def get(
        self,
        _request: HttpRequest,
        pk: UUID,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        try:
            wf = WorkflowDefinition.objects.get(pk=pk)
        except WorkflowDefinition.DoesNotExist:
            raise Http404(f'Workflow {pk} not found')

        meta = wf.definition

        # Strip out our auto‑IDs; keep only type+params for wizard
        steps = [
            {'type': node['type'], 'params': node.get('params', {})}
            for node in meta.get('nodes', [])
        ]

        # Build scopes list with names
        scopes_out: list[dict[str, str]] = []
        for sc in wf.scopes.all():
            if sc.ca_id:
                ca = IssuingCaModel.objects.get(pk=sc.ca_id)
                scopes_out.append({'type': 'CA',     'id': str(sc.ca_id),     'name': ca.unique_name})
            elif sc.domain_id:
                dom = DomainModel.objects.get(pk=sc.domain_id)
                scopes_out.append({'type': 'Domain', 'id': str(sc.domain_id), 'name': dom.unique_name})
            elif sc.device_id:
                dev = DeviceModel.objects.get(pk=sc.device_id)
                scopes_out.append({'type': 'Device', 'id': str(sc.device_id), 'name': dev.common_name})

        return JsonResponse({
            'id':       str(wf.id),
            'name':     wf.name,
            'triggers': meta.get('triggers', []),
            'steps':    steps,
            'scopes':   scopes_out,
        })


class WorkflowDefinitionListView(ListView[WorkflowDefinition]):
    """List all workflow definitions."""
    model = WorkflowDefinition
    template_name = 'workflows/definition_list.html'
    context_object_name = 'definitions'

# TODO(BytesWelder): Do authorization to workflow inputs
class WorkflowWizardView(View):
    """Wizard for creating or editing linear workflows."""
    template_name = 'workflows/definition_wizard.html'

    def get(self, request: HttpRequest) -> HttpResponse:
        # Inject the STEP_PARAM_DEFS JSON into the template context
        return render(
            request,
            self.template_name,
            {'step_param_defs_json': json.dumps(STEP_PARAM_DEFS)},
        )

    def post(self, request: HttpRequest) -> JsonResponse:
        try:
            data: dict[str, Any] = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        wf_id    = data.get('id')
        name     = data.get('name')
        triggers = data.get('triggers')
        steps    = data.get('steps')
        scopes   = data.get('scopes', [])

        if not name or not isinstance(triggers, list) or not isinstance(steps, list):
            return JsonResponse({'error': 'Missing or invalid name, triggers, or steps.'}, status=400)

        definition = transform_to_definition_schema(triggers, steps)

        try:
            if wf_id:
                wf = WorkflowDefinition.objects.get(pk=UUID(wf_id))
                wf.name = name
                wf.definition = definition
                wf.save(update_fields=['name', 'definition', 'updated_at'])
            else:
                wf = WorkflowDefinition.objects.create(
                    name=name,
                    definition=definition,
                    published=True,
                )
        except IntegrityError:
            return JsonResponse({'error': 'A workflow with that name already exists.'}, status=400)

        WorkflowScope.objects.filter(workflow=wf).delete()
        for sc in scopes:
            WorkflowScope.objects.create(
                workflow=wf,
                ca_id=sc.get('ca_id'),
                domain_id=sc.get('domain_id'),
                device_id=sc.get('device_id'),
            )

        return JsonResponse({'id': str(wf.id)}, status=201)


class PendingApprovalsView(ListView[WorkflowInstance]):
    """List all workflow instances awaiting human approval."""
    model = WorkflowInstance
    template_name = 'workflows/pending_list.html'
    context_object_name = 'instances'

    def get_queryset(self) -> Any:
        return WorkflowInstance.objects.filter(state=WorkflowInstance.STATE_PENDING)


class SignalInstanceView(View):
    """API endpoint to signal (approve/reject) a workflow instance."""
    def post(
        self,
        request: HttpRequest,
        instance_id: UUID,
        *args: Any,
        **kwargs: Any
    ) -> JsonResponse:
        try:
            inst = WorkflowInstance.objects.get(id=instance_id)
        except WorkflowInstance.DoesNotExist:
            raise Http404(f'Instance {instance_id} not found')

        action = request.POST.get('action')
        if action not in {'Approved', 'Rejected'}:
            return JsonResponse({'error': 'Invalid action'}, status=400)

        AuditLog.objects.create(
            instance=inst,
            actor=str(request.user),
            action=action,
        )
        advance_instance(inst, signal=action)
        return JsonResponse({'new_state': inst.state})
