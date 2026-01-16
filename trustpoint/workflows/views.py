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
from django.contrib import messages
from django.core.paginator import Page, Paginator
from django.db import IntegrityError, models
from django.db.models import Case, CharField, Count, Value, When
from django.db.models.functions import Cast
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.timezone import now as tz_now
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic import ListView
from trustpoint_core.oid import AlgorithmIdentifier

from devices.models import DeviceModel
from pki.models import DomainModel, IssuingCaModel
from trustpoint.logger import LoggerMixin
from trustpoint.page_context import DEVICES_PAGE_CATEGORY, DEVICES_PAGE_DEVICES_SUBCATEGORY, PageContextMixin
from util.email import MailTemplates
from workflows.context.registry import get_strategy
from workflows.events import Events
from workflows.filters import UnifiedRequestFilterForm, UnifiedRequestFilters
from workflows.models import (
    BADGE_MAP,
    DeviceRequest,
    EnrollmentRequest,
    State,
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowScope,
    get_status_badge,
)
from workflows.services.context import build_context
from workflows.services.context_catalog import build_catalog
from workflows.services.engine import advance_instance
from workflows.services.validators import validate_wizard_payload
from workflows.services.wizard import transform_to_definition_schema

if TYPE_CHECKING:
    from collections.abc import Iterable

    from django.db.models.query import QuerySet

class WizardContextCatalogView(View):
    """Return a handler-driven ctx variable catalog for the wizard (design-time).

    Query params:
        handler: required
        protocol: optional
        operation: optional
    """

    def get(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return a design-time context variable catalog for the wizard.

        Args:
            request: The HTTP request providing query parameters.
            *_args: Unused positional arguments.
            **_kwargs: Unused keyword arguments.

        Returns:
            JsonResponse containing the handler name and a list of context groups.
        """
        handler = (request.GET.get('handler') or '').strip()
        protocol = (request.GET.get('protocol') or '').strip()
        operation = (request.GET.get('operation') or '').strip()

        if not handler:
            return JsonResponse({'error': 'Missing required query param: handler'}, status=400)

        strategy = get_strategy(handler)

        getter = getattr(strategy, 'get_design_time_groups', None)
        groups = getter(protocol=protocol or None, operation=operation or None) if callable(getter) else []

        return JsonResponse({'handler': handler, 'groups': groups}, safe=True)


class RuntimeContextCatalogView(View, LoggerMixin):
    """Return a flattened runtime ctx catalog for a specific WorkflowInstance (debug)."""

    def get(self, _request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> JsonResponse:
        """Return a flattened runtime context catalog for a workflow instance.

        Args:
            _request: The HTTP request (unused).
            instance_id: The workflow instance UUID.
            *_args: Unused positional arguments.
            **_kwargs: Unused keyword arguments.

        Returns:
            JsonResponse containing a flattened context catalog or an error payload.
        """
        inst = get_object_or_404(
            WorkflowInstance.objects.select_related(
                'definition',
                'enrollment_request',
                'enrollment_request__device',
                'enrollment_request__domain',
                'enrollment_request__ca',
                'device_request',
                'device_request__device',
                'device_request__domain',
                'device_request__ca',
            ),
            pk=instance_id,
        )

        try:
            ctx = build_context(inst)
            catalog = build_catalog(ctx)
        except Exception:
            self.logger.exception('runtime context catalog failed (instance_id=%s)', instance_id)
            return JsonResponse(
                {
                    'error': 'Failed to build runtime catalog.',
                    'instance_id': str(instance_id),
                    'usage': 'Insert variables using {{ ctx.<path> }}',
                    'vars': [],
                },
                status=500,
            )

        catalog['instance'] = {
            'id': str(inst.id),
            'workflow': str(inst.definition.name),
            'state': str(inst.state),
            'current_step': str(inst.current_step),
        }
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
        self._validate_export_schema(data.get('schema'), errs)

        # 2) name
        name = self._extract_export_name(data)

        # 3) definition object
        definition = data.get('definition')
        if not isinstance(definition, dict):
            errs.append('"definition" must be an object with "events" and "steps".')
            return errs, None

        # 4) events / steps raw lists
        events_in, steps_in = self._extract_export_events_and_steps(definition, errs)

        # 5) validate/normalize events and steps
        events_out = self._normalize_export_events(events_in, errs)
        steps_out = self._normalize_export_steps(steps_in, errs)

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

    @staticmethod
    def _validate_export_schema(schema: Any, errs: list[str]) -> None:
        if schema != 'trustpoint.workflow/1':
            errs.append('Unsupported or missing "schema". Expected "trustpoint.workflow/1".')

    @staticmethod
    def _extract_export_name(data: dict[str, Any]) -> str:
        name = str(data.get('name') or '').strip()
        if not name:
            name = 'Imported Workflow'  # fallback; not fatal
        return name

    @staticmethod
    def _extract_export_events_and_steps(
        definition: dict[str, Any],
        errs: list[str],
    ) -> tuple[list[Any], list[Any]]:
        events_in = definition.get('events')
        steps_in = definition.get('steps')

        if not isinstance(events_in, list):
            errs.append('"definition.events" must be a list.')
            events_in = []

        if not isinstance(steps_in, list):
            errs.append('"definition.steps" must be a list.')
            steps_in = []

        return events_in, steps_in

    @staticmethod
    def _normalize_export_events(events_in: list[Any], errs: list[str]) -> list[dict[str, str]]:
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

            events_out.append(
                {
                    'handler': handler,
                    'protocol': protocol,
                    'operation': operation,
                }
            )
        return events_out

    @staticmethod
    def _normalize_export_steps(steps_in: list[Any], errs: list[str]) -> list[dict[str, Any]]:
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
        return steps_out

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


class WorkflowWizardView(View, LoggerMixin):
    """UI wizard to create or edit a linear workflow."""

    template_name = 'workflows/definition_wizard.html'

    def _dbg_step_id_keys(self, payload: dict[str, Any]) -> None:
        """Temporary debug helper: log which step-id keys exist in the incoming payload."""
        try:
            # support both flat and nested shapes
            d = payload.get('definition')
            if isinstance(d, dict) and isinstance(d.get('definition'), dict):
                d = d['definition']
            if not isinstance(d, dict):
                d = payload

            steps = d.get('steps') if isinstance(d.get('steps'), list) else payload.get('steps')
            if not isinstance(steps, list):
                self.logger.warning('WIZARD DEBUG: no steps list found. top_keys=%s', list(payload.keys()))
                return

            sample = []
            for i, s in enumerate(steps, start=1):
                if not isinstance(s, dict):
                    sample.append({'i': i, 'type': type(s).__name__})
                    continue
                keys = sorted(s.keys())
                # show the common id-ish keys and their values
                idish = {k: s.get(k) for k in ('id', 'uid', 'key', 'step_id', 'stepId') if k in s}
                sample.append({'i': i, 'keys': keys, 'idish': idish, 'type': s.get('type')})

        except Exception:
            self.logger.exception('WIZARD DEBUG: failed to inspect payload')

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
            self._dbg_step_id_keys(data)
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


class WorkflowInstanceDetailView(PageContextMixin, View):
    """Show detailed info for a workflow instance, including steps and request details."""

    template_name = 'workflows/instance_detail.html'

    def get(self, request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> HttpResponse:
        """Render the workflow instance detail page."""
        inst = self._get_instance(instance_id)
        payload = inst.payload or {}

        enr = inst.enrollment_request
        dr = inst.device_request

        ca, dm, dv = self._resolve_scope_objects(payload, enr, dr)
        protocol, operation = self._resolve_protocol_operation(payload, enr, dr)

        steps, current_step_label = self._build_steps(inst)

        csr_pem = payload.get('csr_pem')
        csr_info = self._parse_csr_info(csr_pem)

        runtime_catalog_url = reverse('workflows:runtime_context_catalog', kwargs={'instance_id': inst.id})

        context = self._build_template_context(
            inst=inst,
            payload=payload,
            enr=enr,
            dr=dr,
            ca=ca,
            dm=dm,
            dv=dv,
            protocol=protocol,
            operation=operation,
            steps=steps,
            current_step_label=current_step_label,
            csr_info=csr_info,
            csr_pem=csr_pem,
            runtime_catalog_url=runtime_catalog_url,
        )
        return render(request, self.template_name, context)

    # ---------------------- helpers ---------------------- #

    @staticmethod
    def _get_instance(instance_id: UUID) -> WorkflowInstance:
        return get_object_or_404(
            WorkflowInstance.objects.select_related(
                'definition',
                'enrollment_request',
                'enrollment_request__device',
                'enrollment_request__domain',
                'enrollment_request__ca',
                'device_request',
                'device_request__device',
                'device_request__domain',
                'device_request__ca',
            ),
            pk=instance_id,
        )

    @staticmethod
    def _resolve_model(model_cls: type[models.Model], payload_id: Any, fallback: Any) -> Any:
        if payload_id:
            return get_object_or_404(model_cls, pk=payload_id)
        return fallback

    def _resolve_scope_objects(
        self,
        payload: dict[str, Any],
        enr: EnrollmentRequest | None,
        dr: DeviceRequest | None,
    ) -> tuple[IssuingCaModel | None, DomainModel | None, DeviceModel | None]:
        fallback_ca = (enr.ca if enr and enr.ca_id else None) or (dr.ca if dr and dr.ca_id else None)
        fallback_dm = (enr.domain if enr and enr.domain_id else None) or (dr.domain if dr and dr.domain_id else None)
        fallback_dv = (enr.device if enr and enr.device_id else None) or (dr.device if dr and dr.device_id else None)

        ca = self._resolve_model(IssuingCaModel, payload.get('ca_id'), fallback_ca)
        dm = self._resolve_model(DomainModel, payload.get('domain_id'), fallback_dm)
        dv = self._resolve_model(DeviceModel, payload.get('device_id'), fallback_dv)
        return ca, dm, dv

    @staticmethod
    def _resolve_protocol_operation(
        payload: dict[str, Any],
        enr: EnrollmentRequest | None,
        dr: DeviceRequest | None,
    ) -> tuple[str | None, str | None]:
        protocol = payload.get('protocol') or (enr.protocol if enr else None) or ('device' if dr else None)
        operation = payload.get('operation') or (enr.operation if enr else None) or (dr.action if dr else None)
        return protocol, operation

    @staticmethod
    def _extract_error(ctx: dict[str, Any]) -> str | None:
        if not isinstance(ctx, dict):
            return None

        err = ctx.get('error')
        if isinstance(err, str) and err.strip():
            return err.strip()

        for k in ('message', 'detail', 'reason'):
            v = ctx.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()

        if isinstance(err, dict):
            msg = err.get('message') or err.get('detail') or err.get('reason')
            if isinstance(msg, str) and msg.strip():
                return msg.strip()

        return None

    def _build_steps(self, inst: WorkflowInstance) -> tuple[list[dict[str, Any]], str | None]:
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

            normalized_error = self._extract_error(ctx)

            details = dict(ctx)
            details.pop('status', None)
            details.pop('ok', None)
            details['error'] = normalized_error

            steps.append(
                {
                    'id': step_id,
                    'label': step_label,
                    'type': step_type,
                    'status': display_status,
                    'badge_class': badge_class,
                    'error': normalized_error,
                    'details': details,
                }
            )

        return steps, current_step_label

    @staticmethod
    def _parse_csr_info(csr_pem: Any) -> dict[str, Any] | None:
        if not (isinstance(csr_pem, str) and csr_pem.strip()):
            return None

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
            return {
                'subject': csr_obj.subject.rfc4514_string(),
                'common_name': cn,
                'sans': sans,
                'key_algorithm': csr_obj.public_key().__class__.__name__,
                'signature_algorithm': f'{sig_alg.verbose_name}, {sig_alg.dotted_string}',
            }
        except Exception as exc:  # noqa: BLE001
            return {'error': f'Failed to parse CSR: {exc!s}'}

    @staticmethod
    def _build_template_context(  # noqa: PLR0913
        *,
        inst: WorkflowInstance,
        payload: dict[str, Any],
        enr: EnrollmentRequest | None,
        dr: DeviceRequest | None,
        ca: IssuingCaModel | None,
        dm: DomainModel | None,
        dv: DeviceModel | None,
        protocol: str | None,
        operation: str | None,
        steps: list[dict[str, Any]],
        current_step_label: str | None,
        csr_info: dict[str, Any] | None,
        csr_pem: Any,
        runtime_catalog_url: str,
    ) -> dict[str, Any]:
        return {
            'inst': inst,
            'payload': payload,
            'enr': enr,
            'dr': dr,
            'ca_obj': ca,
            'domain_obj': dm,
            'device_obj': dv,
            'ca_name': ca.unique_name if ca else None,
            'domain_name': dm.unique_name if dm else None,
            'device_name': dv.common_name if dv else None,
            'device_serial_number': dv.serial_number if dv else None,
            'protocol': protocol,
            'operation': operation,
            'steps': steps,
            'current_step_label': current_step_label,
            'csr_info': csr_info,
            'csr_pem': csr_pem,
            'can_signal': (
                not inst.finalized
                and inst.state == State.AWAITING
                and inst.enrollment_request is not None
                and inst.enrollment_request.aggregated_state == State.AWAITING
            ),
            'runtime_catalog_url': runtime_catalog_url,
            'page_category': 'workflows',
            'page_name': 'pending',
            'clm_url': f'{DEVICES_PAGE_CATEGORY}:{DEVICES_PAGE_DEVICES_SUBCATEGORY}_certificate_lifecycle_management',
        }


class SignalInstanceView(View):
    """Endpoint to signal (approve/reject) a workflow instance via POST."""

    def post(self, request: HttpRequest, instance_id: UUID, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Handle approval or rejection of a single workflow instance."""
        inst = get_object_or_404(WorkflowInstance, pk=instance_id)
        action = request.POST.get('action')
        if action not in {'approve', 'reject'}:
            messages.error(request, f'Invalid action: {action!r}')
            return redirect('workflows:requests')

        if not inst.enrollment_request:
            raise ValueError

        if inst.finalized:
            messages.error(request, f'Workflow {inst.id} was already completed.')

            if not isinstance(inst.enrollment_request, EnrollmentRequest):
                msg = f'No EnrollmentRequest for inst {inst} found'
                raise ValueError(msg)

            return redirect('workflows:request_detail', pk=inst.enrollment_request.pk)

        if inst.enrollment_request.aggregated_state != State.AWAITING:
            messages.error(request,
                           _(f'You can not {action} a workflow where request is already in state \
                            "{inst.enrollment_request.aggregated_state.lower()}"'))  # noqa: INT001

            return redirect('workflows:request_detail', pk=inst.enrollment_request.pk)

        advance_instance(inst, signal=action)
        inst.enrollment_request.recompute_and_save()
        inst.refresh_from_db()

        if action == 'approve':
            messages.success(request, f'Workflow {inst.id} approved and advanced.')
        else:
            messages.warning(request, f'Workflow {inst.id} was rejected.')

        return redirect('workflows:request_detail', pk=inst.enrollment_request.pk)

class DeviceRequestDetailView(ListView[WorkflowInstance]):
    """Show WorkflowInstances that belong to a single DeviceRequest."""
    model = WorkflowInstance
    template_name = 'workflows/device_request_detail.html'
    context_object_name = 'instances'
    paginate_by = 50

    def get_queryset(self) -> QuerySet[WorkflowInstance]:
        """Return WorkflowInstances for the requested DeviceRequest."""
        dr = get_object_or_404(DeviceRequest, pk=self.kwargs['pk'])
        return (
            WorkflowInstance.objects.filter(device_request=dr)
            .select_related(
                'definition',
                'device_request',
                'device_request__device',
                'device_request__domain',
                'device_request__ca',
            )
            .order_by('-created_at')
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Expose the parent DeviceRequest and page metadata."""
        context = super().get_context_data(**kwargs)
        dr = get_object_or_404(
            DeviceRequest.objects.select_related('device', 'domain', 'ca'),
            pk=self.kwargs['pk'],
        )
        context['dr'] = dr
        context['page_category'] = 'workflows'
        context['page_name'] = 'requests'
        return context


class UnifiedRequestListView(View):
    """Render a unified list of enrollment and device requests with filtering and pagination."""

    template_name = 'workflows/unified_request_table.html'
    paginate_by = 25

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the unified request list."""
        form = UnifiedRequestFilterForm(request.GET)
        form.is_valid()
        flt = UnifiedRequestFilters.from_form(form)

        badge_case = self._build_badge_case()

        ers_rows = self._build_enrollment_rows(flt, badge_case)
        drs_rows = self._build_device_rows(flt, badge_case)

        unified = self._choose_unified_queryset(flt, ers_rows, drs_rows)
        unified = self._apply_sorting(unified, request)

        page_obj = self._paginate(unified, request)

        return render(
            request,
            self.template_name,
            {
                'page_obj': page_obj,
                'requests': page_obj.object_list,
                'filter_form': form,
                'page_category': 'workflows',
                'page_name': 'pending_requests',
                'preserve_qs': request.GET.urlencode(),
            },
        )

    # ---------------------- helpers ---------------------- #

    @staticmethod
    def _build_badge_case() -> Case:
        return Case(
            *[When(aggregated_state=k, then=Value(v[1])) for k, v in BADGE_MAP.items()],
            default=Value('bg-secondary text-light'),
            output_field=CharField(),
        )

    @staticmethod
    def _build_enrollment_rows(flt: UnifiedRequestFilters, badge_case: Case) -> QuerySet[Any]:
        ers = EnrollmentRequest.objects.select_related(
            'device', 'domain', 'ca').annotate(instance_count=Count('instances')
            )

        if not flt.include_finalized:
            ers = ers.filter(finalized=False)
        if flt.state:
            ers = ers.filter(aggregated_state=flt.state)
        if flt.device_name:
            ers = ers.filter(device__common_name__icontains=flt.device_name)
        if flt.domain_id is not None:
            ers = ers.filter(domain_id=flt.domain_id)
        if flt.protocol:
            ers = ers.filter(protocol__icontains=flt.protocol)
        if flt.operation:
            ers = ers.filter(operation__icontains=flt.operation)
        if flt.template:
            ers = ers.filter(template__icontains=flt.template)
        if flt.requested_from:
            ers = ers.filter(created_at__gte=flt.requested_from)
        if flt.requested_to:
            ers = ers.filter(created_at__lte=flt.requested_to)

        return (
            ers.annotate(
                request_type=Value('Enrollment', output_field=CharField()),
                template_text=Cast('template', output_field=CharField()),
                badge_css=badge_case,
            )
            .values(
                'id',
                'created_at',
                'aggregated_state',
                'finalized',
                'request_type',
                'protocol',
                'operation',
                'template_text',
                'instance_count',
                'device_id',
                'domain_id',
                'device__common_name',
                'device__serial_number',
                'domain__unique_name',
                'badge_css',
            )
        )

    @staticmethod
    def _build_device_rows(flt: UnifiedRequestFilters, badge_case: Case) -> QuerySet[Any]:
        drs = DeviceRequest.objects.select_related('device', 'domain', 'ca').annotate(instance_count=Count('instances'))

        if not flt.include_finalized:
            drs = drs.filter(finalized=False)
        if flt.state:
            drs = drs.filter(aggregated_state=flt.state)
        if flt.device_name:
            drs = drs.filter(device__common_name__icontains=flt.device_name)
        if flt.domain_id is not None:
            drs = drs.filter(domain_id=flt.domain_id)
        if flt.requested_from:
            drs = drs.filter(created_at__gte=flt.requested_from)
        if flt.requested_to:
            drs = drs.filter(created_at__lte=flt.requested_to)
        if flt.operation:
            drs = drs.filter(action__icontains=flt.operation)

        return (
            drs.annotate(
                request_type=Value('Device', output_field=CharField()),
                protocol=Value('device', output_field=CharField()),
                operation=Cast('action', output_field=CharField()),
                template_text=Value('', output_field=CharField()),
                badge_css=badge_case,
            )
            .values(
                'id',
                'created_at',
                'aggregated_state',
                'finalized',
                'request_type',
                'protocol',
                'operation',
                'template_text',
                'instance_count',
                'device_id',
                'domain_id',
                'device__common_name',
                'device__serial_number',
                'domain__unique_name',
                'badge_css',
            )
        )

    @staticmethod
    def _choose_unified_queryset(
        flt: UnifiedRequestFilters,
        ers_rows: QuerySet[Any],
        drs_rows: QuerySet[Any],
    ) -> QuerySet[Any]:
        if flt.type == 'Enrollment':
            return ers_rows
        if flt.type == 'Device':
            return drs_rows
        return ers_rows.union(drs_rows, all=True)

    @staticmethod
    def _apply_sorting(unified: QuerySet[Any], request: HttpRequest) -> QuerySet[Any]:
        sort = (request.GET.get('sort') or '-created_at').strip()
        allowed_sorts = {'created_at', 'aggregated_state', 'request_type'}

        reverse = sort.startswith('-')
        key = sort.lstrip('-')
        if key not in allowed_sorts:
            key = 'created_at'
            reverse = True

        return unified.order_by(f'-{key}' if reverse else key)

    def _paginate(self, unified: QuerySet[Any], request: HttpRequest) -> Page[Any]:
        paginator = Paginator(unified, self.paginate_by)
        return paginator.get_page(request.GET.get('page'))


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


def _parse_selected_rows(values: list[str]) -> tuple[list[UUID], list[UUID]]:
    """Return (enrollment_ids, device_ids) from checkbox values."""
    enr: list[UUID] = []
    dev: list[UUID] = []

    for raw in values:
        if not raw:
            continue
        try:
            typ, sid = raw.split(':', 1)
            uid = UUID(sid)
        except (ValueError, TypeError):
            continue

        if typ == 'Enrollment':
            enr.append(uid)
        elif typ == 'Device':
            dev.append(uid)

    return enr, dev

class BulkAbortEnrollmentRequestsView(View):
    """Abort multiple enrollment/device requests selected in the UI."""
    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Abort all selected requests and redirect back to the request table."""
        selected = request.POST.getlist('row_checkbox')
        if not selected:
            messages.warning(request, 'Please select at least one request.')
            return redirect('workflows:request_table')

        enr_ids, dev_ids = _parse_selected_rows(selected)

        aborted = 0

        for er in EnrollmentRequest.objects.filter(id__in=enr_ids, finalized=False):
            er.abort()
            aborted += 1

        for dr in DeviceRequest.objects.filter(id__in=dev_ids, finalized=False):
            dr.abort()
            aborted += 1

        if aborted == 0:
            messages.warning(request, 'No abortable requests were found.')
        else:
            messages.success(request, f'Aborted {aborted} request(s).')

        return redirect('workflows:request_table')


class SignalEnrollmentRequestView(View):
    """Approve or reject all workflow instances belonging to a single EnrollmentRequest."""

    def post(self, request: HttpRequest, er_id: UUID, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Handle approval or rejection of all workflow instances in an enrollment request.

        Args:
            request: The HTTP request containing the action.
            er_id: The id of the enrollment request.

        Returns:
            HttpResponse redirecting back to the request table.
        """
        action = request.POST.get('action')
        if action not in {'approve', 'reject'}:
            messages.error(request, f'Invalid action: {action!r}')
            return redirect('workflows:request_table')

        er = get_object_or_404(
            EnrollmentRequest.objects.prefetch_related('instances'),
            pk=er_id,
        )

        if er.finalized:
            messages.error(request, 'Request is already finalized.')
            return redirect('workflows:request_table')

        if er.aggregated_state != State.AWAITING:
            messages.error(
                request,
                _('You cannot %s a request already in state: "%s"') % (
                    action,
                    er.aggregated_state.lower(),
                )
            )

        insts = list(er.instances.select_related('enrollment_request'))

        if action == 'approve':
            failed = [i for i in insts if i.state == State.FAILED]
            if failed:
                messages.error(request, 'You cannot approve a request containing failed instances.')
                return redirect('workflows:request_table')

        for inst in insts:
            advance_instance(inst, signal=action)
            inst.refresh_from_db()

        er.recompute_and_save()

        if action == 'approve':
            messages.success(request, f'Request {er.id} approved.')
        else:
            messages.warning(request, f'Request {er.id} rejected.')

        return redirect('workflows:request_table')


class BulkSignalEnrollmentRequestsView(View):
    """Approve or reject multiple requests selected in the UI."""

    def post(self, request: HttpRequest, *_args: Any, **_kwargs: Any) -> HttpResponseRedirect:
        """Apply an approve/reject action to all selected requests and redirect back to the request table."""
        action = self._get_action_or_redirect(request)
        if isinstance(action, HttpResponseRedirect):
            return action

        selected = request.POST.getlist('row_checkbox')
        if not selected:
            messages.warning(request, 'Please select at least one request.')
            return redirect('workflows:request_table')

        enr_ids, dev_ids = _parse_selected_rows(selected)

        enr_qs = EnrollmentRequest.objects.filter(id__in=enr_ids).prefetch_related('instances')
        dev_qs = DeviceRequest.objects.filter(id__in=dev_ids).prefetch_related('instances')

        if not self._validate_bulk_action(request, action, enr_qs, dev_qs):
            return redirect('workflows:request_table')

        updated = self._apply_bulk_action(action, enr_qs, dev_qs)
        self._report_bulk_result(request, action, updated)
        return redirect('workflows:request_table')

    # ---------------------- helpers ---------------------- #

    @staticmethod
    def _get_action_or_redirect(request: HttpRequest) -> str | HttpResponseRedirect:
        action = request.POST.get('action')
        if action not in {'approve', 'reject'}:
            messages.error(request, f'Invalid bulk action: {action!r}')
            return redirect('workflows:request_table')
        return action

    @staticmethod
    def _validate_bulk_action(
        request: HttpRequest,
        action: str,
        enr_qs: QuerySet[EnrollmentRequest],
        dev_qs: QuerySet[DeviceRequest],
    ) -> bool:
        for er in enr_qs:
            ok = BulkSignalEnrollmentRequestsView._validate_single_request(request, action, er)
            if not ok:
                return False

        for dr in dev_qs:
            ok = BulkSignalEnrollmentRequestsView._validate_single_request(request, action, dr)
            if not ok:
                return False

        return True

    @staticmethod
    def _validate_single_request(request: HttpRequest, action: str, req: Any) -> bool:
        if req.finalized:
            messages.error(request, 'Cannot update finalized requests.')
            return False
        if req.aggregated_state != State.AWAITING:
            messages.error(
                request,
                _('You cannot %s a request already in state "%s"') % (action, req.aggregated_state.lower()),
            )
            return False
        if action == 'approve' and any(inst.state == State.FAILED for inst in req.instances.all()):
            messages.error(request, 'Cannot approve requests containing failed instances.')
            return False
        return True

    @staticmethod
    def _apply_bulk_action(
        action: str,
        enr_qs: QuerySet[EnrollmentRequest],
        dev_qs: QuerySet[DeviceRequest],
    ) -> int:
        updated = 0

        for er in enr_qs:
            BulkSignalEnrollmentRequestsView._signal_instances(action, er.instances.all())
            er.recompute_and_save()
            updated += 1

        for dr in dev_qs:
            BulkSignalEnrollmentRequestsView._signal_instances(action, dr.instances.all())
            dr.recompute_and_save()
            updated += 1

        return updated

    @staticmethod
    def _signal_instances(action: str, instances: Iterable[WorkflowInstance]) -> None:
        for inst in instances:
            advance_instance(inst, signal=action)
            inst.refresh_from_db()

    @staticmethod
    def _report_bulk_result(request: HttpRequest, action: str, updated: int) -> None:
        if updated == 0:
            messages.warning(request, 'No requests were updated.')
        elif action == 'approve':
            messages.success(request, f'{updated} request(s) approved.')
        else:
            messages.warning(request, f'{updated} request(s) rejected.')
