"""Workflow views for TrustPoint.

This module provides Django class-based views for:
- Listing and retrieving workflow definitions, domains, devices, and CAs.
- Managing workflows via a wizard and delete endpoint.
- Displaying pending approvals and workflow instance details.
- Signaling workflow instances (approve/reject).
"""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING, Any
from uuid import UUID

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID
from devices.models import DeviceModel
from django.contrib import messages
from django.db import IntegrityError, models
from django.db.models import Count
from django.db.models.query import QuerySet
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
    QueryDict,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.timezone import now as tz_now
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic import ListView
from pki.models import DomainModel, IssuingCaModel
from trustpoint.page_context import DEVICES_PAGE_CATEGORY, DEVICES_PAGE_DEVICES_SUBCATEGORY, PageContextMixin
from trustpoint_core.oid import AlgorithmIdentifier
from util.email import MailTemplates

from workflows.events import Events
from workflows.filters import EnrollmentRequestFilter, WorkflowFilter
from workflows.models import (
    EnrollmentRequest,
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowScope,
    get_status_badge,
)
from workflows.services.context import build_context
from workflows.services.context_catalog import build_catalog
from workflows.services.engine import advance_instance
from workflows.services.request_aggregator import recompute_request_state
from workflows.services.validators import validate_wizard_payload
from workflows.services.wizard import transform_to_definition_schema

if TYPE_CHECKING:
    from django.db.models import QuerySet


class ContextCatalogView(View):
    """Return a flattened, searchable catalog of {{ ctx.* }} variables for a running instance."""

    def get(self, _request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return JSON catalog of available template paths for {{ ctx.* }}.

        Args:
            _request: The HTTP request.
            instance_id: Workflow instance UUID.

        Returns:
            JsonResponse with 'usage' and 'vars' (each var has key, label, sample).
        """
        inst = get_object_or_404(WorkflowInstance, pk=instance_id)
        ctx = build_context(inst)  # returns a dict
        catalog = build_catalog(ctx)
        return JsonResponse(catalog, safe=True)


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
            groups.append(
                {
                    'key': group_key,
                    'label': group_key.replace('_', ' ').title(),
                    'templates': [{'key': t.key, 'label': t.label} for t in tpl_tuple],
                }
            )
        return JsonResponse({'groups': groups})


class EventsListView(View):
    """API endpoint returning all events."""

    def get(self, _request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return JSON with all available events.

        Args:
            _request: The HTTP request.
            *_args: Unused positional args.
            **_kwargs: Unused keyword args.

        Returns:
            A JsonResponse containing events keyed by event ID.
        """
        data = {
            e.key: {
                'protocol': e.protocol,
                'operation': e.operation,
                'handler': e.handler,
            }
            for e in Events.all()
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
        steps = [{'type': n['type'], 'params': n.get('params', {})} for n in meta.get('steps', [])]

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
                'events': meta.get('events', []),
                'steps': steps,
                'scopes': scopes_out,
            }
        )


class WorkflowDefinitionListView(ListView[WorkflowDefinition]):
    """Show all workflow definitions."""

    model = WorkflowDefinition
    template_name = 'workflows/definition_table.html'
    context_object_name = 'definitions'

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add page metadata to context."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'workflows'
        context['page_name'] = 'definitions'
        return context


class WorkflowDefinitionImportView(View):
    """Accepts a JSON file exported from this system and stages a one-time wizard prefill.

    UX:
      - On success → message.success + redirect to wizard (the wizard loads and clears prefill).
      - On error   → message.error   + redirect back to the definition list (keeps user in UI).
    """

    MAX_ERRORS_TO_SHOW = 6  # avoid spamming too many details

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Handle upload of a workflow export and stage wizard prefill.

        Args:
            request: The HTTP request containing the uploaded JSON file.

        Returns:
            HttpResponse redirecting back to the definition table or wizard.
        """
        f = request.FILES.get('file')
        if not f:
            messages.error(request, 'Please choose a JSON file to import.')
            return redirect('workflows:definition_table')

        try:
            raw = f.read().decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            messages.error(request, 'The uploaded file is not valid UTF-8 text.')
            return redirect('workflows:definition_table')

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            messages.error(request, f'Invalid JSON: line {e.lineno}, col {e.colno}.')
            return redirect('workflows:definition_table')

        # Validate export bundle and convert to wizard prefill
        errors, prefill = self._validate_and_transform_export(data)

        if errors:
            # Trim and show a concise list
            shown = errors[: self.MAX_ERRORS_TO_SHOW]
            for err in shown:
                messages.error(request, err)
            if len(errors) > self.MAX_ERRORS_TO_SHOW:
                messages.error(request, f'(+{len(errors) - self.MAX_ERRORS_TO_SHOW} more issues)')
            return redirect('workflows:definition_table')

        # Stage prefill and go to wizard
        request.session['wizard_prefill'] = prefill
        request.session.modified = True
        messages.success(
            request, 'Workflow imported. The wizard has been prefilled—please review, set scopes, and save or publish.'
        )
        return redirect('workflows:definition_wizard')

    # ---- helpers ----

    def _validate_and_transform_export(self, data: dict[str, Any]) -> tuple[list[str], dict[str, Any] | None]:
        """Returns (errors, prefill) where prefill is.

        { name, events: [{handler, protocol, operation}], steps: [{type, params}], scopes:{} }
        """
        errs: list[str] = []

        # 1) schema
        schema = data.get('schema')
        if schema != 'trustpoint.workflow/1':
            errs.append('Unsupported or missing "schema". Expected "trustpoint.workflow/1".')

        # 2) name
        name = str(data.get('name') or '').strip()
        if not name:
            name = 'Imported Workflow'  # fallback; not fatal

        # 3) definition
        definition = data.get('definition')
        if not isinstance(definition, dict):
            errs.append('"definition" must be an object with "events" and "steps".')
            return errs, None

        events_in = definition.get('events')
        steps_in = definition.get('steps')

        if not isinstance(events_in, list):
            errs.append('"definition.events" must be a list.')
            events_in = []

        if not isinstance(steps_in, list):
            errs.append('"definition.steps" must be a list.')
            steps_in = []

        # 4) validate events (soft, but informative)
        events_out: list[dict[str, str]] = []
        for i, t in enumerate(events_in):
            if not isinstance(t, dict):
                errs.append(f'events[{i}] must be an object.')
                continue
            handler = str(t.get('handler') or '')
            protocol = str(t.get('protocol') or '')
            operation = str(t.get('operation') or '')
            if not handler or not protocol or not operation:
                errs.append(f'events[{i}] is missing "handler", "protocol", or "operation".')
            events_out.append({'handler': handler, 'protocol': protocol, 'operation': operation})

        # 5) validate steps
        steps_out: list[dict[str, Any]] = []
        for i, n in enumerate(steps_in):
            if not isinstance(n, dict):
                errs.append(f'steps[{i}] must be an object with "type" and "params".')
                continue
            typ = str(n.get('type') or '')
            par = n.get('params') or {}
            if not typ:
                errs.append(f'steps[{i}] is missing non-empty "type".')
            if not isinstance(par, dict):
                errs.append(f'steps[{i}].params must be an object.')
                par = {}
            steps_out.append({'type': typ, 'params': par})

        # 6) At least something meaningful?
        if not steps_out:
            errs.append('No steps found in "definition.steps".')

        if errs:
            return errs, None

        prefill = {
            'name': name,
            'events': events_out,
            'steps': steps_out,
            'scopes': {},  # never import scopes; user will choose for this environment
        }
        return [], prefill


class WizardPrefillView(View):
    """Returns and CLEARS a one-time wizard prefill from the session."""

    def get(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return and clear any staged wizard prefill from the session."""
        payload = request.session.pop('wizard_prefill', None)
        request.session.modified = True
        return JsonResponse(payload or {}, safe=True)


class WorkflowDefinitionExportView(View):
    """Download a single workflow definition as a JSON file.

    {
      "schema": "trustpoint.workflow/1",
      "name": "...",
      "version": 1,
      "published": true/false,
      "definition": {...},
      "scopes": [{"ca_id":..., "domain_id":..., "device_id":...}, ...],
      "exported_at": "ISO-8601"
    }
    """

    def get(self, _request: HttpRequest, pk: UUID, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Return a JSON file export for the given workflow definition."""
        wf = get_object_or_404(WorkflowDefinition, pk=pk)

        # Serialize scopes (raw IDs only—names are environment-specific)
        scopes = [
            {'ca_id': s.ca_id, 'domain_id': s.domain_id, 'device_id': s.device_id}
            for s in wf.scopes.all().order_by('ca_id', 'domain_id', 'device_id')
        ]

        bundle = {
            'schema': 'trustpoint.workflow/1',
            'name': wf.name,
            'version': wf.version,
            'published': wf.published,
            'definition': wf.definition,
            'scopes': scopes,
            'exported_at': tz_now().isoformat(),
        }

        body = json.dumps(bundle, ensure_ascii=False, indent=2)
        filename = f'workflow-{wf.name.replace(" ", "_")}-{wf.id}.json'

        resp = HttpResponse(body, content_type='application/json; charset=utf-8')
        resp['Content-Disposition'] = f'attachment; filename="{filename}"'
        return resp


class WorkflowDefinitionPublishView(View):
    """Toggle published flag via POST (publish/unpublish)."""

    def post(self, request: HttpRequest, pk: UUID, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Publish or pause a workflow definition based on the submitted action."""
        wf = get_object_or_404(WorkflowDefinition, pk=pk)
        action = (request.POST.get('action') or '').lower()
        if action == 'publish':
            wf.published = True
            wf.save(update_fields=['published', 'updated_at'])
            messages.success(request, f'Workflow "{wf.name}" published.')
        elif action == 'pause':
            wf.published = False
            wf.save(update_fields=['published', 'updated_at'])
            messages.info(request, f'Workflow "{wf.name}" paused (saved as draft).')
        else:
            messages.error(request, 'Invalid publish action.')
        return redirect('workflows:definition_table')


class WorkflowWizardView(View):
    """UI wizard to create or edit a linear workflow."""

    template_name = 'workflows/definition_wizard.html'

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the workflow definition wizard page."""
        return render(
            request,
            self.template_name,
            {'page_category': 'workflows', 'page_name': 'wizard'},
        )

    def post(self, request: HttpRequest) -> JsonResponse:
        """Validate and save a workflow definition submitted from the wizard."""
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        errors = validate_wizard_payload(data)
        if errors:
            return JsonResponse({'error': 'Validation failed', 'errors': errors}, status=400)

        name, events_typed, steps_typed, scopes_list = self._parse_payload_for_save(data)
        definition = transform_to_definition_schema(events_typed, steps_typed)
        scopes_list = self._dedupe_scopes(scopes_list)

        # NEW: published flag from payload (default to False = draft)
        published_flag = bool(data.get('published', False))

        wf_id_raw = data.get('id')
        try:
            if wf_id_raw:
                wf = WorkflowDefinition.objects.get(pk=UUID(str(wf_id_raw)))
                wf.name = name
                wf.definition = definition
                wf.published = published_flag
                wf.save(update_fields=['name', 'definition', 'published', 'updated_at'])
            else:
                wf = WorkflowDefinition.objects.create(
                    name=name,
                    definition=definition,
                    published=published_flag,
                )
        except IntegrityError:
            return JsonResponse({'error': 'A workflow with that name already exists.'}, status=400)

        # Reset scopes idempotently
        wf.scopes.all().delete()
        WorkflowScope.objects.bulk_create(
            [
                WorkflowScope(
                    workflow=wf,
                    ca_id=sc.get('ca_id'),
                    domain_id=sc.get('domain_id'),
                    device_id=sc.get('device_id'),
                )
                for sc in scopes_list
            ]
        )

        return JsonResponse({'id': str(wf.id)}, status=201)

    @staticmethod
    def _parse_payload_for_save(
        data: dict[str, Any],
    ) -> tuple[str, list[dict[str, str]], list[dict[str, Any]], list[dict[str, Any]]]:
        name = str(data.get('name') or '').strip()

        events_raw = list(data.get('events') or [])
        events_typed: list[dict[str, str]] = [
            {
                'handler': str((t or {}).get('handler', '')),
                'protocol': str((t or {}).get('protocol', '')),
                'operation': str((t or {}).get('operation', '')),
            }
            for t in events_raw
        ]

        steps_raw = list(data.get('steps') or [])
        steps_typed: list[dict[str, Any]] = [
            {'type': str((s or {}).get('type', '')), 'params': dict((s or {}).get('params') or {})} for s in steps_raw
        ]

        scopes_in = data.get('scopes', {})
        scopes_list = WorkflowWizardView._flatten_scopes(scopes_in)

        return name, events_typed, steps_typed, scopes_list

    @staticmethod
    def _flatten_scopes(scopes_in: Any) -> list[dict[str, Any]]:
        if isinstance(scopes_in, dict):
            out: list[dict[str, Any]] = []
            out.extend({'ca_id': ca, 'domain_id': None, 'device_id': None} for ca in scopes_in.get('ca_ids', []))
            out.extend({'ca_id': None, 'domain_id': dom, 'device_id': None} for dom in scopes_in.get('domain_ids', []))
            out.extend({'ca_id': None, 'domain_id': None, 'device_id': dev} for dev in scopes_in.get('device_ids', []))
            return out
        if isinstance(scopes_in, list):
            return [dict(x) for x in scopes_in]
        return []

    @staticmethod
    def _dedupe_scopes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate rows (same CA/Domain/Device triple)."""
        seen: set[tuple[int | None, int | None, int | None]] = set()
        unique: list[dict[str, Any]] = []
        for it in items:
            ca = it.get('ca_id')
            dom = it.get('domain_id')
            dev = it.get('device_id')
            key = (
                int(ca) if isinstance(ca, (int,)) or (isinstance(ca, str) and ca.isdigit()) else None,
                int(dom) if isinstance(dom, (int,)) or (isinstance(dom, str) and dom.isdigit()) else None,
                int(dev) if isinstance(dev, (int,)) or (isinstance(dev, str) and dev.isdigit()) else None,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append({'ca_id': key[0], 'domain_id': key[1], 'device_id': key[2]})
        return unique


class WorkflowDefinitionDeleteView(View):
    """POST-only: deletes the WorkflowDefinition."""

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
        return redirect('workflows:definition_table')


class PendingApprovalsView(ListView[WorkflowInstance]):
    """Show workflow instances with a default state filter of AwaitingApproval."""

    model = WorkflowInstance
    template_name = 'workflows/pending_table.html'
    context_object_name = 'instances'

    filterset_class = WorkflowFilter
    default_sort_param = '-created_at'  # newest first

    def get_queryset(self) -> QuerySet[WorkflowInstance]:
        """Return instances with default 'AwaitingApproval' filter applied when none given."""
        base_qs = WorkflowInstance.objects.select_related(
            'definition',
            'enrollment_request',
            'enrollment_request__device',
            'enrollment_request__domain',
        )

        params = self.request.GET.copy()
        if not params:
            params = QueryDict(mutable=True)
            params['state'] = WorkflowInstance.STATE_AWAITING  # default

        self.filterset = self.filterset_class(params, queryset=base_qs)
        qs: QuerySet[WorkflowInstance] = self.filterset.qs

        allowed_sorts = {
            'enrollment_request__device__common_name',
            '-enrollment_request__device__common_name',
            'enrollment_request__domain__unique_name',
            '-enrollment_request__domain__unique_name',
            'enrollment_request__protocol',
            '-enrollment_request__protocol',
            'definition__name',
            '-definition__name',
            'created_at',
            '-created_at',
            'state',
            '-state',
        }
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        if sort_param not in allowed_sorts:
            sort_param = self.default_sort_param
        return qs.order_by(sort_param)

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add page metadata, filter, and sorting information to the context."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'workflows'
        context['page_name'] = 'waiting_approvals'
        context['clm_url'] = (
            f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management'
        )
        sort_param = self.request.GET.get('sort', self.default_sort_param)
        context['current_sort'] = sort_param
        context['filter'] = getattr(self, 'filterset', None)

        params = self.request.GET.copy()
        params.pop('sort', None)
        context['preserve_qs'] = params.urlencode()
        return context


class WorkflowInstanceDetailView(PageContextMixin, View):
    """Show detailed info for a pending workflow instance, including step summary."""

    template_name = 'workflows/instance_detail.html'

    def get(self, request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Render the detail view for a single workflow instance."""
        inst = get_object_or_404(
            WorkflowInstance.objects.select_related(
                'definition',
                'enrollment_request',
                'enrollment_request__device',
                'enrollment_request__domain',
                'enrollment_request__ca',
            ),
            pk=instance_id,
        )

        payload = inst.payload or {}

        # ---- Resolve CA / Domain / Device -------------------------------------
        def _resolve(model_cls: type[models.Model], payload_id: Any, fallback: Any) -> Any:
            """Resolve a model instance from payload or fall back to the given value."""
            if payload_id:
                return get_object_or_404(model_cls, pk=payload_id)
            return fallback

        enr = inst.enrollment_request
        ca = _resolve(IssuingCaModel, payload.get('ca_id'), enr.ca if enr and enr.ca_id else None)
        dm = _resolve(DomainModel, payload.get('domain_id'), enr.domain if enr and enr.domain_id else None)
        dv = _resolve(DeviceModel, payload.get('device_id'), enr.device if enr and enr.device_id else None)

        # ---- Steps + step contexts -------------------------------------------
        steps_raw = inst.get_steps()
        step_contexts: dict[str, dict[str, Any]] = inst.step_contexts or {}

        try:
            current_idx = inst.get_current_step_index()
        except Exception:  # noqa: BLE001
            current_idx = None

        steps: list[dict[str, Any]] = []
        current_step_label: str | None = None

        for idx0, step_def in enumerate(steps_raw):
            step_id = step_def.get('id') or f'step-{idx0 + 1}'
            step_type = step_def.get('type', 'Unknown')
            step_label = step_def.get('name') or step_def.get('label') or step_id

            ctx = step_contexts.get(step_id, {}) or {}
            raw_status = ctx.get('status', '')
            display_status, badge_class = get_status_badge(raw_status)

            if current_idx is not None and idx0 == current_idx:
                current_step_label = step_label

            error_value = ctx.get('error')
            details = {
                k: v
                for k, v in ctx.items()
                if k not in {'status', 'ok'}
            }

            steps.append(
                {
                    'label': step_label,
                    'type': step_type,
                    'status': display_status,
                    'badge_class': badge_class,
                    'error': error_value,
                    'details': details,
                }
            )

        # ---- CSR parsing ------------------------------------------------------
        csr_info: dict[str, Any] | None = None
        csr_pem = payload.get('csr_pem')
        if isinstance(csr_pem, str) and csr_pem.strip():
            try:
                csr_obj = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))

                cn_attrs = csr_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn = cn_attrs[0].value if cn_attrs else None

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

        instance_badge = inst.badge_class
        enrollment_badge = inst.enrollment_request.badge_class

        context = {
            'inst': inst,
            'payload': payload,
            'ca_name': ca.unique_name if ca else None,
            'domain_name': dm.unique_name if dm else None,
            'device_name': dv.common_name if dv else None,
            'device_serial_number': dv.serial_number if dv else None,
            'csr_info': csr_info,
            'csr_pem': csr_pem,
            'steps': steps,
            'current_step_label': current_step_label,
            'can_signal': (
                not inst.finalized
                and inst.state == WorkflowInstance.STATE_AWAITING
                and inst.enrollment_request is not None
                and inst.enrollment_request.aggregated_state == EnrollmentRequest.STATE_AWAITING
            ),
            'page_category': 'workflows',
            'page_name': 'pending',
            'clm_url': f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management',
            'instance_badge': instance_badge,
            'enrollment_badge': enrollment_badge,
        }
        return render(request, self.template_name, context)


class SignalInstanceView(View):
    """Endpoint to signal (approve/reject) a workflow instance via POST."""

    def post(self, request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Handle approval or rejection of a single workflow instance."""
        inst = get_object_or_404(WorkflowInstance, pk=instance_id)
        action = request.POST.get('action')
        if action not in {'approve', 'reject'}:
            messages.error(request, f'Invalid action: {action!r}')
            return redirect('workflows:pending_table')

        if inst.finalized:
            messages.error(request, f'Workflow {inst.id} was already completed.')
            return redirect('workflows:pending_table')

        if not inst.enrollment_request:
            raise ValueError

        if inst.enrollment_request.aggregated_state != EnrollmentRequest.STATE_AWAITING:
            messages.error(request,
                           _(f'You can not {action} a workflow where request is already in state \
                            "{inst.enrollment_request.aggregated_state.lower()}"'))  # noqa: INT001
            return redirect('workflows:pending_table')

        advance_instance(inst, signal=action)
        inst.refresh_from_db()
        if inst.enrollment_request:
            with contextlib.suppress(Exception):
                recompute_request_state(inst.enrollment_request)

        if action == 'approve':
            messages.success(request, f'Workflow {inst.id} approved and advanced.')
        else:
            messages.warning(request, f'Workflow {inst.id} was rejected.')

        return redirect('workflows:pending_table')


class BulkSignalInstancesView(View):
    """Endpoint to signal (approve/reject) multiple workflow instances via POST."""

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Handles the POST request for bulk approval/rejection.

        Args:
            request: The django request object.
            _args: Positional arguments are discarded.
            kwargs: Keyword arguments are passed to get_context_data.

        Returns:
            The HttpResponseRedirect.
        """
        action = request.POST.get('action')
        if action not in {'approve', 'reject'}:
            messages.error(request, f'Invalid bulk action: {action!r}')
            return redirect('workflows:pending_table')

        # Checkboxes use name="row_checkbox"
        selected_ids: list[str] = request.POST.getlist('row_checkbox')

        if not selected_ids:
            messages.warning(request, 'Please select at least one workflow instance.')
            return redirect('workflows:pending_table')

        instances_qs = WorkflowInstance.objects.filter(
            id__in=selected_ids,
        ).select_related('enrollment_request')

        if any(s.finalized for s in instances_qs):
            messages.error(request, 'You can not update completed workflows.')
            return redirect('workflows:pending_table')

        invalid_enrollment_qs = instances_qs.exclude(
            enrollment_request__aggregated_state=EnrollmentRequest.STATE_AWAITING
        ).first()

        if invalid_enrollment_qs is not None:
            # If there is no enrollment_request at all, treat as not allowed as well
            if invalid_enrollment_qs.enrollment_request is None:
                state_label = _('unknown')
            else:
                state_label = invalid_enrollment_qs.enrollment_request.aggregated_state.lower()

            messages.error(
                request,
                _(
                    'You can not approve/reject a workflow where request is already in state "%(state)s"'
                ) % {'state': state_label},
            )
            return redirect('workflows:pending_table')

        if action == 'Approved':
            rejected_instances = instances_qs.filter(state=WorkflowInstance.STATE_FAILED)

            if rejected_instances.exists():
                messages.error(request, 'You cannot approve failed instances.')
                return redirect('workflows:pending_table')

        if not instances_qs.exists():
            messages.warning(request, 'No pending workflow instances matched your selection.')
            return redirect('workflows:pending_table')

        updated_count = 0

        for inst in instances_qs:
            advance_instance(inst, signal=action)
            inst.refresh_from_db()
            if inst.enrollment_request:
                with contextlib.suppress(Exception):
                    recompute_request_state(inst.enrollment_request)
            updated_count += 1

        if updated_count == 0:
            messages.warning(request, 'No workflow instances were updated.')
        elif action == 'Approved':
            messages.success(
                request,
                f'{updated_count} workflow instance(s) approved and advanced.',
            )
        else:
            messages.warning(
                request,
                f'{updated_count} workflow instance(s) rejected.',
            )

        return redirect('workflows:pending_table')


class EnrollmentRequestListView(ListView[EnrollmentRequest]):
    """List EnrollmentRequests (main pending requests page)."""

    model = EnrollmentRequest
    template_name = 'workflows/enrollment_request_table.html'
    context_object_name = 'requests'
    paginate_by = 25

    def get_queryset(self) -> QuerySet[EnrollmentRequest]:
        """Return EnrollmentRequests annotated with workflow instance counts, filtered."""
        base_qs = (
            EnrollmentRequest.objects.select_related('device', 'domain', 'ca')
            .annotate(workflow_count=Count('instances'))
            .order_by('-created_at')
        )

        params = self.request.GET.copy()
        if not params:
            params = QueryDict(mutable=True)
            params['finalized'] = 'False'
        self.filterset = EnrollmentRequestFilter(params or None, queryset=base_qs)
        qs: QuerySet[EnrollmentRequest] = self.filterset.qs


        return qs

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add page metadata and filter to context."""
        context = super().get_context_data(**kwargs)
        context['page_category'] = 'workflows'
        context['page_name'] = 'pending_requests'
        context['filter'] = getattr(self, 'filterset', None)
        # preserve query string when changing sort/pagination if needed later
        params = self.request.GET.copy()
        context['preserve_qs'] = params.urlencode()
        return context


class EnrollmentRequestDetailView(ListView[WorkflowInstance]):
    """Show WorkflowInstances that belong to a single EnrollmentRequest."""

    model = WorkflowInstance
    template_name = 'workflows/enrollment_request_detail.html'
    context_object_name = 'instances'
    paginate_by = 50

    def get_queryset(self) -> QuerySet[WorkflowInstance]:
        """Return WorkflowInstances for the requested EnrollmentRequest."""
        er = get_object_or_404(EnrollmentRequest, pk=self.kwargs['pk'])
        return (
            WorkflowInstance.objects.filter(enrollment_request=er)
            .select_related(
                'definition',
                'enrollment_request',
                'enrollment_request__device',
                'enrollment_request__domain',
                'enrollment_request__ca',
            )
            .order_by('-created_at')
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Expose the parent EnrollmentRequest and page metadata."""
        context = super().get_context_data(**kwargs)
        er = get_object_or_404(
            EnrollmentRequest.objects.select_related('device', 'domain', 'ca'),
            pk=self.kwargs['pk'],
        )
        context['er'] = er
        context['page_category'] = 'workflows'
        context['page_name'] = 'requests'
        return context


class BulkAbortEnrollmentRequestsView(View):
    """POST endpoint to abort multiple EnrollmentRequests."""

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Handles the POST request for bulk abortion of enrollment requests.

        Args:
            request: The django request object.
            _args: Positional arguments are discarded.
            kwargs: Keyword arguments are passed to get_context_data.

        Returns:
            The HttpResponseRedirect.
        """
        selected_ids: list[str] = request.POST.getlist('row_checkbox')
        if not selected_ids:
            messages.warning(request, 'Please select at least one request.')
            return redirect('workflows:request_table')

        # Only abort non-finalized requests
        qs = EnrollmentRequest.objects.filter(id__in=selected_ids, finalized=False)

        if not qs.exists():
            messages.warning(request, 'No abortable enrollment requests were found.')
            return redirect('workflows:request_table')

        aborted_count = 0
        for er in qs:
            er.abort()
            aborted_count += 1

        if aborted_count == 0:
            messages.warning(request, 'No enrollment requests were aborted.')
        else:
            messages.success(request, f'Aborted {aborted_count} enrollment request(s).')

        return redirect('workflows:request_table')
