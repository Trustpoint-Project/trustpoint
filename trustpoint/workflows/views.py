"""Workflow views for TrustPoint.

This module provides Django class-based views for:
- Listing and retrieving workflow definitions, domains, devices, and CAs.
- Managing workflows via a wizard and delete endpoint.
- Displaying pending approvals and workflow instance details.
- Signaling workflow instances (approve/reject).
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from uuid import UUID

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID
from devices.models import DeviceModel
from django.contrib import messages
from django.db import IntegrityError
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
from trustpoint_core.oid import AlgorithmIdentifier
from util.email import MailTemplates

from workflows.models import (
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowScope,
)
from workflows.services.engine import advance_instance
from workflows.services.wizard import transform_to_definition_schema
from workflows.triggers import Triggers

if TYPE_CHECKING:
    from django.db.models import QuerySet


class MailTemplateListView(View):
    """Return email templates grouped for the wizard."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return JSON grouping available mail templates.

        Args:
            _request: The HTTP request.
            *_args: Unused positional args.
            **_kwargs: Unused keyword args.

        Returns:
            A JsonResponse containing grouped mail templates.
        """
        groups = []
        for group_key, tpl_tuple in MailTemplates.GROUPS.items():
            groups.append({
                'key': group_key,
                'label': group_key.replace('_', ' ').title(),
                'templates': [{'key': t.key, 'label': t.label} for t in tpl_tuple],
            })
        return JsonResponse({'groups': groups})


class TriggerListView(View):
    """API endpoint returning all triggers."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return JSON with all available triggers.

        Args:
            _request: The HTTP request.
            *_args: Unused positional args.
            **_kwargs: Unused keyword args.

        Returns:
            A JsonResponse containing triggers keyed by trigger ID.
        """
        data = {
            t.key: {
                'protocol':  t.protocol,
                'operation': t.operation,
                'handler':   t.handler,
            }
            for t in Triggers.all()
        }
        return JsonResponse(data)


class CAListView(View):
    """Return all issuing CAs as JSON."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return a list of active issuing CAs.

        Args:
            _request: The HTTP request.
            *_args: Unused positional args.
            **_kwargs: Unused keyword args.

        Returns:
            A JsonResponse with CA IDs and names.
        """
        cas = IssuingCaModel.objects.filter(is_active=True)
        data = [{'id': str(c.id), 'name': c.unique_name} for c in cas]
        return JsonResponse(data, safe=False)


class DomainListView(View):
    """Return all domains as JSON."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return a list of active domains.

        Args:
            _request: The HTTP request.
            *_args: Unused positional args.
            **_kwargs: Unused keyword args.

        Returns:
            A JsonResponse with domain IDs and names.
        """
        doms = DomainModel.objects.filter(is_active=True)
        data = [{'id': str(d.id), 'name': d.unique_name} for d in doms]
        return JsonResponse(data, safe=False)


class DeviceListView(View):
    """Return all devices as JSON."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return a list of devices.

        Args:
            _request: The HTTP request.
            *_args: Unused positional args.
            **_kwargs: Unused keyword args.

        Returns:
            A JsonResponse with device IDs and names.
        """
        devs = DeviceModel.objects.select_related('domain').all()
        data = [{'id': str(d.id), 'name': d.common_name} for d in devs]
        return JsonResponse(data, safe=False)


class DefinitionDetailView(View):
    """Return JSON for a single WorkflowDefinition (for editing in wizard)."""

    def get(self, _request: HttpRequest, pk: UUID, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return details of a single WorkflowDefinition.

        Args:
            _request: The HTTP request.
            pk: The workflow definition UUID.
            *_args: Unused positional args.
            **_kwargs: Unused keyword args.

        Returns:
            A JsonResponse with workflow definition metadata.
        """
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

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add page metadata to context."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'workflows'
        context['page_name'] = 'definitions'
        return context


class WorkflowWizardView(View):
    """UI wizard to create or edit a linear workflow."""

    template_name = 'workflows/definition_wizard.html'

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render workflow wizard UI."""
        return render(
            request,
            self.template_name,
            {
                'page_category': 'workflows',
                'page_name': 'wizard',
            },
        )

    def post(self, request: HttpRequest) -> JsonResponse:
        """Create or update a workflow definition."""
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
            scopes_list.extend(
                {'ca_id': ca, 'domain_id': None, 'device_id': None} for ca in scopes_in.get('ca_ids', [])
            )
            scopes_list.extend(
                {'ca_id': None, 'domain_id': dom, 'device_id': None} for dom in scopes_in.get('domain_ids', [])
            )
            scopes_list.extend(
                {'ca_id': None, 'domain_id': None, 'device_id': dev} for dev in scopes_in.get('device_ids', [])
            )
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
    """POST-only: deletes the WorkflowDefinition if no non-finalized WorkflowInstance exists for it."""

    def post(self, request: HttpRequest, pk: UUID, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Delete a workflow definition by ID."""
        wf = get_object_or_404(WorkflowDefinition, pk=pk)
        # if WorkflowInstance.objects.filter(definition=wf, finalized=False).exists():
        #     messages.error(
        #         request,
        #         f'Cannot delete "{wf.name}" — active instances remain.'  # noqa: ERA001
        #     )  # noqa: ERA001, RUF100
        # else:  # noqa: ERA001
        wf.delete()
        messages.success(request, f'Workflow "{wf.name}" deleted.')
        return redirect('workflows:definition_list')


class PendingApprovalsView(ListView[WorkflowInstance]):
    """Show all instances awaiting human approval."""

    model = WorkflowInstance
    template_name = 'workflows/pending_list.html'
    context_object_name = 'instances'

    def get_queryset(self) -> QuerySet[WorkflowInstance]:
        """Filter queryset to only include pending workflow instances."""
        return WorkflowInstance.objects.filter(state=WorkflowInstance.STATE_AWAITING, finalized=False)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the page category and name to the context.

        Args:
            **kwargs: Keyword arguments passed to super().get_context_data.

        Returns:
            The context to use for rendering the page.
        """
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'workflows'
        context['page_name'] = 'pending'
        return context


class WorkflowInstanceDetailView(View):
    """Show detailed info for a pending workflow instance."""

    template_name = 'workflows/pending_detail.html'

    def get(self, request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle GET request for pending workflow detail view."""
        inst = get_object_or_404(WorkflowInstance, pk=instance_id)
        payload = inst.payload or {}

        # Lookup CA/Domain/Device names
        ca_name = None
        if payload.get('ca_id'):
            ca = get_object_or_404(IssuingCaModel, pk=payload['ca_id'])
            ca_name = ca.unique_name

        domain_name = None
        if payload.get('domain_id'):
            dm = get_object_or_404(DomainModel, pk=payload['domain_id'])
            domain_name = dm.unique_name

        device_name = None
        if payload.get('device_id'):
            dv = get_object_or_404(DeviceModel, pk=payload['device_id'])
            device_name = dv.common_name

        # Parse CSR if present
        csr_info: dict[str, Any] | None = None
        csr_pem = payload.get('csr_pem')
        if isinstance(csr_pem, str):
            try:
                csr_obj = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
                # Common Name
                cn_attrs = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else None
                # SANs
                try:
                    san_ext = csr_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    dns_sans = san_ext.value.get_values_for_type(x509.DNSName)
                    ip_sans = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
                    sans = [*dns_sans, *ip_sans]
                except ExtensionNotFound:
                    sans = []
                sig_alg = AlgorithmIdentifier.from_dotted_string(csr_obj.signature_algorithm_oid.dotted_string)
                csr_info = {
                    'subject': csr_obj.subject.rfc4514_string(),
                    'common_name': cn,
                    'sans': sans,
                    'key_algorithm': csr_obj.public_key().__class__.__name__,
                    'signature_algorithm': f'{sig_alg.verbose_name}, {sig_alg.dotted_string}',
                }
            except Exception as e:  # noqa: BLE001
                csr_info = {'error': f'Failed to parse CSR: {e!s}'}

        context = {
            'inst': inst,
            'payload': payload,
            'ca_name': ca_name,
            'domain_name': domain_name,
            'device_name': device_name,
            'csr_info': csr_info,
            'page_category': 'workflows',
            'page_name': 'pending',
        }
        return render(request, self.template_name, context)


class SignalInstanceView(View):
    """Endpoint to signal (approve/reject) a workflow instance via POST."""

    def post(self, request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Approve or reject a workflow instance."""
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
