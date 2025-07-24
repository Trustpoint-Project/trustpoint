# workflows/services/orchestrator.py
from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from typing import Any, Dict, Optional

from cryptography import x509
from django.db import transaction

from workflows.models import (
    AuditLog,
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowScope,
)

logger = logging.getLogger(__name__)


def handle_certificate_request(
    *,
    protocol: str,
    operation: str,
    ca_id: int | uuid.UUID,
    domain_id: int | uuid.UUID,
    device_id: int | uuid.UUID,
    payload: Dict[str, Any],
    **_: Any,
) -> Dict[str, Any]:
    """- Computes a stable fingerprint over the CSRs TBS bytes.

    - If there is already a COMPLETED instance with that fingerprint, returns {'status':'completed'}.
    - Otherwise, for each published workflow definition:
        • Skips it if it has no nodes.
        • Matches triggers and scopes.
        • Deduplicates any running (non REJECTED) instance.
        • Creates (or reuses) an instance, advances it, and returns {'status':'pending','instance_id':...}.
    - If no definition matches, returns {'status':'no_match'}.
    """
    # 1) Compute stable fingerprint over CSR Info
    csr_pem = payload.get('csr_pem')
    if not isinstance(csr_pem, str):
        return {'status': 'error', 'msg': 'could not load csr_pem'}
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    fingerprint = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()

    # 2) Check for an already‑completed instance
    completed = WorkflowInstance.objects.filter(
        payload__fingerprint=fingerprint,
        state=WorkflowInstance.STATE_COMPLETED,
    ).first()
    if completed:
        return {'status': 'completed'}

    # 3) Iterate through published definitions
    definitions = WorkflowDefinition.objects.filter(published=True)
    for definition in definitions:
        # skip definitions with no nodes
        nodes = definition.definition.get('nodes') or []
        if not nodes:
            logger.warning('Skipping workflow %r because it has no nodes', definition.name)
            continue

        # trigger match
        triggers = definition.definition.get('triggers', [])
        if not any(
            t.get('protocol') == protocol and t.get('operation') == operation
            for t in triggers
        ):
            continue

        # scope match
        for scope in WorkflowScope.objects.filter(workflow=definition):
            if scope.ca_id not in (None, ca_id):
                continue
            if scope.domain_id not in (None, domain_id):
                continue
            if scope.device_id not in (None, device_id):
                continue

            # assemble full payload
            full_payload: Dict[str, Any] = {
                'protocol': protocol,
                'operation': operation,
                'ca_id': ca_id,
                'domain_id': domain_id,
                'device_id': device_id,
                'fingerprint': fingerprint,
                **{k: v for k, v in payload.items() if k != 'csr_b64'},
            }

            # deduplicate running instances
            existing = WorkflowInstance.objects.filter(
                definition=definition,
                payload__fingerprint=fingerprint,
            ).exclude(
                state=WorkflowInstance.STATE_REJECTED,
            ).first()

            # first node in the graph
            start_node = nodes[0]['id']

            with transaction.atomic():
                if existing:
                    inst = existing
                else:
                    inst = WorkflowInstance.objects.create(
                        definition=definition,
                        current_node=start_node,
                        state=WorkflowInstance.STATE_STARTED,
                        payload=full_payload,
                    )
                    AuditLog.objects.create(
                        instance=inst,
                        action='Started',
                        details=full_payload,
                    )

            # advance from the start node
            advance_instance(inst)

            return {'status': 'pending', 'instance_id': str(inst.id)}

    return {'status': 'no_match'}



def advance_instance(
    instance: WorkflowInstance,
    signal: Optional[str] = None,
) -> None:
    """Advance the instance to its next node/state, given an optional signal."""
    from workflows.services.executors import NodeExecutorFactory

    definition_meta = instance.definition.definition
    node_meta = next(
        n for n in definition_meta['nodes']
        if n['id'] == instance.current_node
    )

    executor = NodeExecutorFactory.create(node_meta['type'])
    next_node, next_state = executor.execute(instance, signal)

    instance.current_node = next_node or instance.current_node
    instance.state = next_state
    instance.save(update_fields=['current_node', 'state'])
