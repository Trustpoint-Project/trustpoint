# workflows/services/certificate_request.py

import hashlib
import logging
import uuid
from typing import Any

from cryptography import x509
from django.db import transaction

from workflows.models import (
    AuditLog,
    WorkflowDefinition,
    WorkflowInstance,
)
from workflows.services.engine import advance_instance

logger = logging.getLogger(__name__)


class CertificateRequestHandler:
    """1) Compute a stable CSR fingerprint.

    2) Iterate all published workflows,
       a) skip ones without any nodes
       b) match on trigger (protocol & operation)
       c) match on scope (ca/domain/device), treating NULL as wildcard
    3) For the first match: dedupe or create a WorkflowInstance, advance it, return status.
    """

    def __call__(
        self,
        *,
        protocol: str,
        operation: str,
        ca_id: int | uuid.UUID,
        domain_id: int | uuid.UUID,
        device_id: int | uuid.UUID,
        payload: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        csr_pem = payload.get('csr_pem')
        if not isinstance(csr_pem, str):
            return {'status': 'error', 'msg': 'csr_pem missing'}

        # 1) fingerprint
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        fp = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()

        # 2) loop definitions in Python so we can treat NULL as wildcard
        definitions = WorkflowDefinition.objects.filter(published=True)

        for wf in definitions:
            nodes = wf.definition.get('nodes') or []
            if not nodes:
                logger.warning('Skipping %r: no nodes', wf.name)
                continue

            # 2a) trigger match
            triggers = wf.definition.get('triggers', [])
            if not any(
                t.get('protocol') == protocol and t.get('operation') == operation
                for t in triggers
            ):
                continue

            # 2b) scope match
            for scope in wf.scopes.all():
                if scope.ca_id is not None and scope.ca_id != ca_id:
                    continue
                if scope.domain_id is not None and scope.domain_id != domain_id:
                    continue
                if scope.device_id is not None and scope.device_id != device_id:
                    continue

                # 3) OK — we’ve found a matching workflow
                # 3a) already completed?
                if WorkflowInstance.objects.filter(
                    definition=wf,
                    payload__fingerprint=fp,
                    state=WorkflowInstance.STATE_COMPLETED,
                ).exists():
                    return {'status': 'completed'}

                # 3b) dedupe pending
                existing = (
                    WorkflowInstance.objects
                    .filter(definition=wf, payload__fingerprint=fp)
                    .exclude(state=WorkflowInstance.STATE_REJECTED)
                    .first()
                )

                start_node = nodes[0]['id']
                full_payload = {
                    'protocol': protocol,
                    'operation': operation,
                    'ca_id': ca_id,
                    'domain_id': domain_id,
                    'device_id': device_id,
                    'fingerprint': fp,
                    **{k: v for k, v in payload.items() if k != 'csr_b64'},
                }

                with transaction.atomic():
                    if existing:
                        inst = existing
                    else:
                        inst = WorkflowInstance.objects.create(
                            definition=wf,
                            current_node=start_node,
                            state=WorkflowInstance.STATE_STARTED,
                            payload=full_payload,
                        )
                        AuditLog.objects.create(
                            instance=inst, action='Started', details=full_payload
                        )

                advance_instance(inst)
                return {'status': 'pending', 'instance_id': str(inst.id)}

        return {'status': 'no_match'}
