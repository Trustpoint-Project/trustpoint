"""Handles the workflow engine logic during a request."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateSigningRequest
from django.db import transaction
from django.db.models import Q

from trustpoint.logger import LoggerMixin
from workflows.models import DeviceRequest, EnrollmentRequest, State, WorkflowDefinition, WorkflowInstance
from workflows.services.engine import advance_instance

if TYPE_CHECKING:
    from request.request_context import RequestContext


class AbstractWorkflowHandler(ABC, LoggerMixin):
    """Abstract base class for workflow handler."""

    @abstractmethod
    def handle(self, context: RequestContext) -> None:
        """Execute workflow logic."""


class WorkflowHandler(ABC, LoggerMixin):
    """Abstract base class for workflow handler."""

    def handle(self, context: RequestContext) -> None:
        """Execute workflow logic."""
        if not context.event:
            self.logger.error('No event found for the Workflow.')
            return

        h = context.event.handler
        if h == 'certificate_request':
            CertificateRequestHandler().handle(context)
        elif h == 'device_action':
            DeviceActionHandler().handle(context)


class DeviceActionHandler(WorkflowHandler):
    """Handles workflow triggers for device lifecycle events."""

    def handle(
        self,
        context: RequestContext,
        payload: dict[str, Any] | None = None,
        **_: Any,
    ) -> None:
        """Handle device action events and trigger workflows accordingly."""
        if not context.device:
            msg = 'DeviceActionHandler requires a device.'
            raise ValueError(msg)

        if not context.operation:
            msg = 'DeviceActionHandler requires an operation.'
            raise ValueError(msg)

        if not payload:
            payload = {}

        # Strict rule: device actions without a domain must not trigger workflows
        domain = context.domain
        if domain is None:
            self.logger.info(
                'Skipping device_action workflow trigger: device=%s has no domain (operation=%s).',
                context.device.pk,
                context.operation,
            )
            context.device_request = None  # type: ignore[attr-defined]
            return

        action = context.operation  # "created", "onboarded", "deleted"
        ca = domain.get_issuing_ca_or_value_error()

        def _norm(v: Any) -> int | None:
            try:
                return int(v) if v is not None else None
            except (TypeError, ValueError):
                return None

        ca_id = _norm(ca.pk)
        domain_id = _norm(domain.pk)
        device_id = _norm(context.device.pk)

        # Determine applicable workflows FIRST:
        # 1) Restrict by event at DB level (prevents "certificate-only" definitions from being scanned here)
        # 2) Apply scope semantics (CA/Domain/Device exact or NULL=any)
        candidates = (
            WorkflowDefinition.objects.filter(published=True)
            .filter(
                definition__events__contains=[
                    {
                        'protocol': 'device',
                        'operation': action,
                    }
                ]
            )
            .filter(
                Q(scopes__ca_id=ca_id) | Q(scopes__ca_id__isnull=True),
                Q(scopes__domain_id=domain_id) | Q(scopes__domain_id__isnull=True),
                Q(scopes__device_id=device_id) | Q(scopes__device_id__isnull=True),
            )
            .distinct()
        )

        # Keep only workflows that have steps
        definitions: list[WorkflowDefinition] = []
        for wf in candidates:
            meta = wf.definition or {}
            steps = meta.get('steps', [])
            if steps:
                definitions.append(wf)

        # New rule: if no workflow applies -> do NOT create a DeviceRequest at all
        if not definitions:
            context.device_request = None  # type: ignore[attr-defined]
            return

        # Create DeviceRequest only once we know it will have at least one workflow instance
        dr = DeviceRequest.objects.create(
            device=context.device,
            domain=domain,
            ca=ca,
            action=action,
            aggregated_state=State.RUNNING,
            finalized=False,
            payload=payload,
        )

        for wf in definitions:
            meta = wf.definition or {}
            steps = meta.get('steps', [])
            if not steps:
                continue

            first_step = steps[0]['id']

            inst = WorkflowInstance.objects.create(
                definition=wf,
                device_request=dr,
                current_step=first_step,
                state=State.RUNNING,
                payload={
                    'operation': action,
                    'protocol': 'device',
                    'device_id': device_id,
                    'domain_id': domain_id,
                    'ca_id': ca_id,
                    **payload,
                },
            )

            advance_instance(inst)
            inst.refresh_from_db()

        # Recompute after children were ensured/advanced
        dr.recompute_and_save()
        dr.refresh_from_db()

        context.device_request = dr  # type: ignore[attr-defined]


class CertificateRequestHandler(WorkflowHandler):
    """Manages workflows triggered by certificate request events."""

    def handle(  # noqa: C901, PLR0912, PLR0915
        self,
        context: RequestContext,
        payload: dict[str, Any] | None = None,
        **_: Any,
    ) -> None:
        """Execute workflow logic."""

        def _norm(v: Any) -> int | None:  # normalize IDs
            try:
                return int(v) if v is not None else None
            except (TypeError, ValueError):
                return None

        if not context.domain:
            raise ValueError
        if not context.device:
            raise ValueError
        if not context.cert_requested:
            raise ValueError
        if not context.protocol:
            raise ValueError
        if not context.operation:
            raise ValueError
        if not payload:
            payload = {}

        csr = context.cert_requested
        if not isinstance(csr, CertificateSigningRequest):
            raise TypeError

        ca_obj = context.domain.get_issuing_ca_or_value_error()

        ca_id = _norm(ca_obj.pk)
        domain_id = _norm(context.domain.pk)
        device_id = _norm(context.device.pk)

        fingerprint = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()
        template = context.cert_profile_str or ''  # TODO: ren. profile throughout EnrollmentRequest

        # 1) Determine applicable workflows FIRST (so we can skip creating empty requests)
        # Restrict by event at DB level to avoid scanning device-action definitions.
        definitions_qs = (
            WorkflowDefinition.objects.filter(published=True)
            .filter(
                definition__events__contains=[
                    {
                        'protocol': context.protocol,
                        'operation': context.operation,
                    }
                ]
            )
            .filter(
                Q(scopes__ca_id=ca_id) | Q(scopes__ca_id__isnull=True),
                Q(scopes__domain_id=domain_id) | Q(scopes__domain_id__isnull=True),
                Q(scopes__device_id=device_id) | Q(scopes__device_id__isnull=True),
            )
            .distinct()
        )
        definitions: list[WorkflowDefinition] = []
        for wf in definitions_qs:
            meta = wf.definition or {}
            steps = meta.get('steps', [])
            if steps:
                definitions.append(wf)


        if not definitions:
            context.enrollment_request = None
            return

        # 2) Find or create an open EnrollmentRequest only if workflows exist
        req = (
            EnrollmentRequest.objects.filter(
                protocol=context.protocol,
                operation=context.operation,
                ca=ca_obj,
                domain=context.domain,
                device=context.device,
                fingerprint=fingerprint,
                template=template,
                finalized=False,
            )
            .order_by('-created_at')
            .first()
        )

        if req is None:
            req = EnrollmentRequest.objects.create(
                protocol=context.protocol,
                operation=context.operation,
                ca=ca_obj,
                domain=context.domain,
                device=context.device,
                fingerprint=fingerprint,
                template=template,
                aggregated_state=State.AWAITING,
                finalized=False,
            )

        # 3) Ensure instances for all applicable definitions
        for wf in definitions:
            meta = wf.definition or {}
            steps = meta.get('steps', [])
            if not steps:
                continue

            inst = (
                WorkflowInstance.objects.filter(
                    definition=wf,
                    enrollment_request=req,
                )
                .order_by('-created_at')
                .first()
            )

            if inst is None:
                first_step = steps[0]['id']
                full_payload = {
                    'protocol': context.protocol,
                    'operation': context.operation,
                    'ca_id': ca_id,
                    'domain_id': domain_id,
                    'device_id': device_id,
                    'fingerprint': fingerprint,
                    'csr_pem': csr.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'),
                    **dict(payload.items()),
                }
                with transaction.atomic():
                    inst = WorkflowInstance.objects.create(
                        definition=wf,
                        enrollment_request=req,
                        current_step=first_step,
                        state=State.RUNNING,
                        payload=full_payload,
                    )

            if inst.state is State.RUNNING:
                advance_instance(inst)
                inst.refresh_from_db()

        # 4) Recompute aggregate after all children were ensured/advanced
        req.recompute_and_save()
        req.refresh_from_db()

        context.enrollment_request = req
