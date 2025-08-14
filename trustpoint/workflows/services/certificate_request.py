# workflows/services/certificate_request.py

from __future__ import annotations

import hashlib
import logging
from typing import Any
from uuid import UUID

from cryptography import x509
from django.db import transaction
from django.db.models import Q

from workflows.models import WorkflowDefinition, WorkflowInstance
from workflows.services.engine import advance_instance
from workflows.services.handler_lookup import register_handler

logger = logging.getLogger(__name__)



@register_handler("certificate_request")
class CertificateRequestHandler:
    """Handle certificate‐request events (e.g. EST simpleenroll).

    1. Compute a stable fingerprint over the CSR’s CertificateRequestInfo.
    2. Find published workflows whose scopes match (None = “any”).
    3. Match the (protocol,operation) trigger.
    4. If a COMPLETED & not‐finalized run exists → finalize it & return COMPLETED.
    5. If an in‐flight run exists → return its current state.
    6. Otherwise create a new instance and advance it once → return its new state.
    7. If nothing matched → return no_match.
    """

    def __call__(
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
        # -- 1) Normalize incoming IDs to ints or None --
        def _norm(val: int | UUID | None) -> int | None:
            if val is None:
                return None
            try:
                return int(val)
            except (TypeError, ValueError):
                return None

        ca = _norm(ca_id)
        dom = _norm(domain_id)
        dev = _norm(device_id)

        # -- 2) Load & fingerprint CSR PEM --
        csr_pem = payload.get('csr_pem')
        if not isinstance(csr_pem, str):
            return {'status': 'error', 'msg': 'Missing or invalid csr_pem'}

        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        except Exception as exc:
            logger.exception('Failed to parse CSR PEM')
            return {'status': 'error', 'msg': f'Invalid CSR: {exc!s}'}

        fingerprint = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()
        logger.debug('CSR fingerprint: %s', fingerprint)

        # -- 3) Scope filter (NULL means “any”) --
        definitions = (
            WorkflowDefinition.objects.filter(published=True)
            .filter(
                Q(scopes__ca_id=ca) | Q(scopes__ca_id__isnull=True),
                Q(scopes__domain_id=dom) | Q(scopes__domain_id__isnull=True),
                Q(scopes__device_id=dev) | Q(scopes__device_id__isnull=True),
            )
            .distinct()
        )
        logger.debug('Found %d workflows matching scope', definitions.count())

        for wf in definitions:
            nodes = wf.definition.get('nodes', [])
            if not nodes:
                logger.warning('Skipping %r: no nodes defined', wf.name)
                continue

            triggers = wf.definition.get('triggers', [])
            if not any(t.get('protocol') == protocol and t.get('operation') == operation for t in triggers):
                continue


            wf_instance = (
                WorkflowInstance.objects.filter(
                    definition=wf,
                    payload__fingerprint=fingerprint,
                    finalized=False,
                )
                .exclude(state__in=[WorkflowInstance.STATE_RUNNING, WorkflowInstance.STATE_RUNNING, WorkflowInstance.STATE_FAILED])
                .first()
            )
            if wf_instance:
                return {'status': wf_instance.state, 'instance_id': str(wf_instance.id)}

            # -- 6) No existing → create new instance at first node, then advance once --
            first_step = nodes[0]['id']
            full_payload = {
                'protocol': protocol,
                'operation': operation,
                'ca_id': ca,
                'domain_id': dom,
                'device_id': dev,
                'fingerprint': fingerprint,
                **{k: v for k, v in payload.items() if k != 'csr_b64'},
            }

            with transaction.atomic():
                inst = WorkflowInstance.objects.create(
                    definition=wf,
                    current_step=first_step,
                    state=WorkflowInstance.STATE_STARTING,
                    payload=full_payload,
                )

            advance_instance(inst)
            return {'status': inst.state, 'instance_id': str(inst.id)}

        # -- 7) Nothing matched --
        return {'status': 'no_match'}
