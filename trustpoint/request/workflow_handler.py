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
from workflows.models import EnrollmentRequest, WorkflowDefinition, WorkflowInstance
from workflows.services.engine import advance_instance
from workflows.services.request_aggregator import recompute_request_state

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
        """Selects correct workflow handler based on event."""
        if not context.event:
            msg = 'No event found for the Workflow.'
            self.logger.error(msg)
        elif context.event.handler == 'certificate_request':
            CertificateRequestHandler().handle(context=context)


class CertificateRequestHandler(WorkflowHandler):
    """Manages workflows triggered by certificate request events."""

    def _validate_context(self, context: RequestContext) -> tuple[bool, str]:
        """Validate the context for the worfklow request handler."""
        if not context.domain:
            return (False, 'No domain found')
        if not context.device:
            return (False, 'No device found')
        if not context.parsed_message:
            return (False, 'No CSR found')

        return (True, '')

    def handle(
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
        template = context.certificate_template

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
                aggregated_state=EnrollmentRequest.STATE_AWAITING,
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
            if not any(t.get('protocol') == context.protocol and t.get('operation') == context.operation for t in events):
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
                        state=WorkflowInstance.STATE_RUNNING,
                        payload=full_payload,
                    )
                created = True

            # Advance fresh/active instances
            if inst.state is WorkflowInstance.STATE_RUNNING:
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
        recompute_request_state(req)
        req.refresh_from_db()

        # If truly no matching definitions, reflect NoMatch
        context.enrollment_request = req
