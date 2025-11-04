from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from cryptography import x509
from django.db import transaction
from django.db.models import Q

from workflows.models import EnrollmentRequest, WorkflowDefinition, WorkflowInstance
from workflows.services.engine import advance_instance
from workflows.services.handler_lookup import register_handler
from workflows.services.request_aggregator import recompute_request_state  # NEW

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)


@register_handler('certificate_request')
class CertificateRequestHandler:
    def __call__(  # noqa: PLR0913
        self,
        *,
        protocol: str,
        operation: str,
        ca_id: int | UUID | None,
        domain_id: int | UUID | None,
        device_id: int | UUID | None,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        def _norm(v: Any) -> int | None:  # normalize IDs
            try:
                return int(v) if v is not None else None
            except (TypeError, ValueError):
                return None

        ca_id = _norm(ca_id)
        domain_id = _norm(domain_id)
        device_id = _norm(device_id)

        csr_pem = payload.get('csr_pem')
        if not isinstance(csr_pem, str):
            return {'status': 'error', 'msg': 'Missing or invalid csr_pem'}
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        except Exception as exc:  # noqa: BLE001
            return {'status': 'error', 'msg': f'Invalid CSR: {exc!s}'}

        fingerprint = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()
        template = str(payload.get('template') or '') or None

        # Find or create an open EnrollmentRequest
        req = (
            EnrollmentRequest.objects.filter(
                protocol=protocol,
                operation=operation,
                ca_id=ca_id,
                domain_id=domain_id,
                device_id=device_id,
                fingerprint=fingerprint,
                template=template,
                finalized=False,
            )
            .exclude(aggregated_state__in=EnrollmentRequest.TERMINAL_STATES)
            .order_by('-created_at')
            .first()
        )

        if req is None:
            req = EnrollmentRequest.objects.create(
                protocol=protocol,
                operation=operation,
                ca_id=ca_id,
                domain_id=domain_id,
                device_id=device_id,
                fingerprint=fingerprint,
                template=template,
                aggregated_state=EnrollmentRequest.STATE_PENDING,
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

            triggers = meta.get('triggers', [])
            if not any(t.get('protocol') == protocol and t.get('operation') == operation for t in triggers):
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
                    'protocol': protocol,
                    'operation': operation,
                    'ca_id': ca_id,
                    'domain_id': domain_id,
                    'device_id': device_id,
                    'fingerprint': fingerprint,
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
        if not per_instance:
            return {
                'status': EnrollmentRequest.STATE_NOMATCH,
                'request_id': str(req.id),
                'instances': [],
            }

        return {
            'status': req.aggregated_state,   # EST will branch on this
            'request_id': str(req.id),
            'instances': per_instance,
        }
