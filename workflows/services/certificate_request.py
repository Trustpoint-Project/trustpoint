# workflows/services/certificate_request.py

import hashlib
import logging
import uuid
from typing import Any

from cryptography import x509
from django.db import transaction

from workflows.models import AuditLog, WorkflowDefinition, WorkflowInstance
from workflows.services.engine import advance_instance
from workflows.services.executors import AbstractNodeExecutor

logger = logging.getLogger(__name__)


class CertificateRequestHandler:
    """Central orchestration for 'certificate_request':
    • match trigger+scope → pick a WorkflowDefinition
    • dedupe/create a WorkflowInstance
    • if brand‑new: auto‑drive it until waiting, error, or completion
    • return unified JSON: instance_id, status, steps[{id,type,state}]
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
            return {'status': 'error', 'error': 'csr_pem missing'}

        # 1) fingerprint
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        fp  = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()

        # 2) find matching definition
        for wf in WorkflowDefinition.objects.filter(published=True):
            nodes = wf.definition.get('nodes', []) or []
            if not nodes:
                logger.warning('Skipping %r: no nodes', wf.name)
                continue

            # trigger match?
            if not any(
                t.get('protocol') == protocol and t.get('operation') == operation
                for t in wf.definition.get('triggers', [])
            ):
                continue

            # scope match (None = wildcard)
            if not any(
                (sc.ca_id     in (None, ca_id)) and
                (sc.domain_id in (None, domain_id)) and
                (sc.device_id in (None, device_id))
                for sc in wf.scopes.all()
            ):
                continue

            # 3) dedupe or create
            inst = WorkflowInstance.objects.filter(
                definition=wf,
                payload__fingerprint=fp
            ).first()

            is_new = inst is None
            if is_new:
                start = nodes[0]['id']
                full_payload = {
                    'protocol':    protocol,
                    'operation':   operation,
                    'ca_id':       ca_id,
                    'domain_id':   domain_id,
                    'device_id':   device_id,
                    'fingerprint': fp,
                    **{k: v for k, v in payload.items() if k != 'csr_pem'},
                }
                step_states = {
                    n['id']: AbstractNodeExecutor.STATE_NOT_STARTED
                    for n in nodes
                }

                with transaction.atomic():
                    inst = WorkflowInstance.objects.create(
                        definition   = wf,
                        current_node = start,
                        state        = WorkflowInstance.STATE_PENDING,
                        payload      = full_payload,
                        step_states  = step_states,
                    )
                    AuditLog.objects.create(
                        instance=inst,
                        action='Started',
                        details=full_payload,
                    )

                # auto‑drive until waiting on an Approval, error, or complete
                for _ in range(len(nodes)):
                    advance_instance(inst)
                    inst.refresh_from_db()
                    if inst.state in (
                        WorkflowInstance.STATE_ERROR,
                        WorkflowInstance.STATE_COMPLETE,
                    ):
                        break
                    curr_state = inst.step_states.get(inst.current_node)
                    if curr_state in (
                        AbstractNodeExecutor.STATE_NOT_STARTED,
                        AbstractNodeExecutor.STATE_WAITING
                    ):
                        break

            # 4) build the response
            steps = []
            for n in nodes:
                st = inst.step_states.get(n['id'], AbstractNodeExecutor.STATE_NOT_STARTED)
                steps.append({
                    'id':    n['id'],
                    'type':  n['type'],
                    'state': st,
                })

            return {
                'instance_id': str(inst.id),
                'status':      inst.state,   # pending | error | complete
                'steps':       steps,
            }

        # no matching workflow
        return {
            'status': 'no_match',
            'error':  'no published workflow for this trigger/scope',
        }
