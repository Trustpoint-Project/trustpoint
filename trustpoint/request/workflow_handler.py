"""Handles the workflow engine logic during a request."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateSigningRequest
from django.db import transaction
from django.db.models import Q

from request.request_context import BaseCertificateRequestContext
from trustpoint.logger import LoggerMixin
from workflows.models import DeviceRequest, EnrollmentRequest, State, WorkflowDefinition, WorkflowInstance
from workflows.services.engine import advance_instance

if TYPE_CHECKING:
    from request.request_context import BaseRequestContext


class AbstractWorkflowHandler(ABC, LoggerMixin):
    """Abstract base class for workflow handler."""

    @abstractmethod
    def handle(self, context: BaseRequestContext) -> None:
        """Execute workflow logic."""


class WorkflowHandler(ABC, LoggerMixin):
    """Abstract base class for workflow handler."""

    def handle(self, context: BaseRequestContext) -> None:
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
        context: BaseRequestContext,
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

        action = context.operation  # "created", "onboarded", "deleted"

        # Domain and CA might be null
        domain = context.domain
        ca = domain.get_issuing_ca_or_value_error() if domain else None

        # Create a new DeviceRequest
        dr = DeviceRequest.objects.create(
            device=context.device,
            domain=domain,
            ca=ca,
            action=action,
            aggregated_state=State.AWAITING,
            finalized=False,
            payload=payload,
        )

        # Find matching workflow definitions
        definitions = [
            wf
            for wf in WorkflowDefinition.objects.filter(published=True)
            if any(
                e.get('protocol') == 'device' and e.get('operation') == action for e in wf.definition.get('events', [])
            )
        ]

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
                    'device_id': context.device.pk,
                    'domain_id': domain.pk if domain else None,
                    'ca_id': ca.pk if ca else None,
                    **payload,
                },
            )

            advance_instance(inst)
            inst.refresh_from_db()

        dr.recompute_and_save()
        context.device_request = dr  # type: ignore[attr-defined]


class CertificateRequestHandler(WorkflowHandler):
    """Manages workflows triggered by certificate request events."""

    def _validate_context(self, context: BaseCertificateRequestContext) -> tuple[bool, str]:
        """Validate the context for the worfklow request handler."""
        if not context.domain:
            return (False, 'No domain found')
        if not context.device:
            return (False, 'No device found')
        if not context.parsed_message:
            return (False, 'No CSR found')

        return (True, '')

    def handle(  # noqa: C901, PLR0912, PLR0915 - Core workflow orchestration requires multiple validation and conditional paths
        self,
        context: BaseRequestContext,
        payload: dict[str, Any] | None = None,
        **_: Any,
    ) -> None:
        """Execute workflow logic."""

        def _norm(v: Any) -> int | None:  # normalize IDs
            try:
                return int(v) if v is not None else None
            except (TypeError, ValueError):
                return None

        if not isinstance(context, BaseCertificateRequestContext):
            msg = 'CertificateRequestHandler requires a BaseCertificateRequestContext.'
            raise TypeError(msg)

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

        ca_id = _norm(context.domain.get_issuing_ca_or_value_error().pk)
        domain_id = _norm(context.domain.pk)
        device_id = _norm(context.device.pk)

        fingerprint = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()
        template = context.cert_profile_str or ''  # TODO: ren. profile throughout EnrollmentRequest  # noqa: E501, FIX002, TD002

        # Find or create an open EnrollmentRequest
        req = (
            EnrollmentRequest.objects.filter(
                protocol=context.protocol,
                operation=context.operation,
                ca=context.domain.get_issuing_ca_or_value_error(),
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
                ca=context.domain.get_issuing_ca_or_value_error(),
                domain=context.domain,
                device=context.device,
                fingerprint=fingerprint,
                template=template,
                aggregated_state=State.AWAITING,
                finalized=False,
            )

        # Scope candidates
        definitions = (
            WorkflowDefinition.objects.filter(published=True)
            .filter(
                Q(scopes__ca_id=ca_id) | Q(scopes__ca_id__isnull=True),
                Q(scopes__domain_id=domain_id) | Q(scopes__domain_id__isnull=True),
                Q(scopes__device_id=device_id) | Q(scopes__device_id__isnull=True),
            )
            .distinct()
        )

        per_instance: list[dict[str, Any]] = []

        for wf in definitions:
            meta = wf.definition or {}
            steps = meta.get('steps', [])
            if not steps:
                continue

            events = meta.get('events', [])
            if not any(
                t.get('protocol') == context.protocol and t.get('operation') == context.operation for t in events
            ):
                continue

            # Reuse regardless of finalized flag (to avoid duplicates forever)
            inst = (
                WorkflowInstance.objects.filter(
                    definition=wf,
                    enrollment_request=req,
                )
                .order_by('-created_at')
                .first()
            )

            created = False
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
                created = True

            # Advance fresh/active instances
            if inst.state is State.RUNNING:
                advance_instance(inst)
                inst.refresh_from_db()

            per_instance.append(
                {
                    'workflow_id': str(wf.id),
                    'workflow_name': wf.name,
                    'instance_id': str(inst.id),
                    'created': created,
                    'state': inst.state,
                }
            )

        # Recompute aggregate after all children were ensured/advanced
        req.recompute_and_save()
        req.refresh_from_db()

        # If truly no matching definitions, reflect NoMatch
        context.enrollment_request = req
