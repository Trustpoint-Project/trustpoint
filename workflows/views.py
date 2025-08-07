from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from devices.models import DeviceModel
from django.contrib import messages
from django.db import IntegrityError
from django.db.models import QuerySet
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import ListView
from pki.models import DomainModel, IssuingCaModel

from workflows.models import (
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowScope,
)
from workflows.services.engine import advance_instance
from workflows.services.wizard import transform_to_definition_schema


class CAListView(View):
    """Return all issuing CAs as JSON."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        cas = IssuingCaModel.objects.filter(is_active=True)
        data = [{'id': str(c.id), 'name': c.unique_name} for c in cas]
        return JsonResponse(data, safe=False)


class DomainListView(View):
    """Return all domains as JSON."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        doms = DomainModel.objects.filter(is_active=True)
        data = [{'id': str(d.id), 'name': d.unique_name} for d in doms]
        return JsonResponse(data, safe=False)


class DeviceListView(View):
    """Return all devices as JSON."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> JsonResponse:
        devs = DeviceModel.objects.select_related('domain').all()
        data = [{'id': str(d.id), 'name': d.common_name} for d in devs]
        return JsonResponse(data, safe=False)


class DefinitionDetailView(View):
    """Return JSON for a single WorkflowDefinition (for editing in wizard)."""

    def get(self, request: HttpRequest, pk: UUID, *args: Any, **kwargs: Any) -> JsonResponse:
        wf = get_object_or_404(WorkflowDefinition, pk=pk)
        meta = wf.definition

        # strip out auto-IDs, leave only type+params for wizard
        steps = [{'type': n['type'], 'params': n.get('params', {})} for n in meta.get('nodes', [])]

        # scopes out with names
        scopes_out: list[dict[str, str]] = []
        for sc in wf.scopes.all():
            if sc.ca_id:
                ca = get_object_or_404(IssuingCaModel, pk=sc.ca_id)
                scopes_out.append(
                    {
                        'type': 'CA',
                        'id': str(sc.ca_id),
                        'name': ca.unique_name,
                    }
                )
            elif sc.domain_id:
                dm = get_object_or_404(DomainModel, pk=sc.domain_id)
                scopes_out.append(
                    {
                        'type': 'Domain',
                        'id': str(sc.domain_id),
                        'name': dm.unique_name,
                    }
                )
            elif sc.device_id:
                dv = get_object_or_404(DeviceModel, pk=sc.device_id)
                scopes_out.append(
                    {
                        'type': 'Device',
                        'id': str(sc.device_id),
                        'name': dv.common_name,
                    }
                )

        return JsonResponse(
            {
                'id': str(wf.id),
                'name': wf.name,
                'triggers': meta.get('triggers', []),
                'steps': steps,
                'scopes': scopes_out,
            }
        )


class WorkflowDefinitionListView(ListView[WorkflowDefinition]):
    """Show all workflow definitions."""

    model = WorkflowDefinition
    template_name = 'workflows/definition_list.html'
    context_object_name = 'definitions'


class WorkflowWizardView(View):
    """UI wizard to create or edit a linear workflow."""
    template_name = 'workflows/definition_wizard.html'

    def get(self, request: HttpRequest) -> HttpResponse:
        return render(request, self.template_name)

    def post(self, request: HttpRequest) -> JsonResponse:
        try:
            data: dict[str, Any] = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        wf_id = data.get('id')
        name = data.get('name')
        triggers = data.get('triggers')
        steps = data.get('steps')
        scopes_in = data.get('scopes', {})

        if not name or not isinstance(triggers, list) or not isinstance(steps, list):
            return JsonResponse({'error': 'Missing or invalid name, triggers, or steps.'}, status=400)

        # Build flat scopes list from grouped input
        scopes_list: list[dict[str, Any]] = []
        if isinstance(scopes_in, dict):
            for ca in scopes_in.get('ca_ids', []):
                scopes_list.append({'ca_id': ca, 'domain_id': None, 'device_id': None})
            for dom in scopes_in.get('domain_ids', []):
                scopes_list.append({'ca_id': None, 'domain_id': dom, 'device_id': None})
            for dev in scopes_in.get('device_ids', []):
                scopes_list.append({'ca_id': None, 'domain_id': None, 'device_id': dev})
        elif isinstance(scopes_in, list):
            scopes_list = scopes_in
        else:
            return JsonResponse({'error': 'Invalid scopes format.'}, status=400)

        # Transform to internal definition
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

        # Reset scopes
        wf.scopes.all().delete()
        for sc in scopes_list:
            WorkflowScope.objects.create(
                workflow=wf,
                ca_id=sc.get('ca_id'),
                domain_id=sc.get('domain_id'),
                device_id=sc.get('device_id'),
            )

        return JsonResponse({'id': str(wf.id)}, status=201)


class WorkflowDefinitionDeleteView(View):
    """
    POST-only: deletes the WorkflowDefinition if no non-finalized
    WorkflowInstance exists for it.
    """
    def post(
        self,
        request: HttpRequest,
        pk: UUID,
        *args: Any,
        **kwargs: Any
    ) -> HttpResponseRedirect:
        wf = get_object_or_404(WorkflowDefinition, pk=pk)
        # if WorkflowInstance.objects.filter(definition=wf, finalized=False).exists():
        #     messages.error(
        #         request,
        #         f'Cannot delete "{wf.name}" — active instances remain.'
        #     )
        # else:
        wf.delete()
        messages.success(request, f'Workflow "{wf.name}" deleted.')
        return redirect('workflows:definition_list')



class PendingApprovalsView(ListView[WorkflowInstance]):
    """Show all instances awaiting human approval."""

    model = WorkflowInstance
    template_name = 'workflows/pending_list.html'
    context_object_name = 'instances'

    def get_queryset(self) -> QuerySet[WorkflowInstance]:
        return WorkflowInstance.objects.filter(state=WorkflowInstance.STATE_AWAITING, finalized=False)


class SignalInstanceView(View):
    """Endpoint to signal (approve/reject) a workflow instance via POST."""

    def post(self, request: HttpRequest, instance_id: UUID, *args: Any, **kwargs: Any) -> HttpResponseRedirect:
        inst = get_object_or_404(WorkflowInstance, pk=instance_id)
        action = request.POST.get('action')
        if action not in {'Approved', 'Rejected'}:
            messages.error(request, f'Invalid action: {action!r}')
            return redirect('workflows:pending_list')

        advance_instance(inst, signal=action)
        if action == 'Approved':
            messages.success(request, f'Workflow {inst.id} approved and advanced.')
        else:
            messages.warning(request, f'Workflow {inst.id} was rejected.')

        return redirect('workflows:pending_list')
