"""Certificate request event handler and workflow trigger."""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from cryptography import x509
from django.db import transaction
from django.db.models import Q

from workflows.models import WorkflowDefinition, WorkflowInstance
from workflows.services.engine import advance_instance
from workflows.services.handler_lookup import register_handler

if TYPE_CHECKING:
    from uuid import UUID

logger = logging.getLogger(__name__)


@register_handler('certificate_request')
class CertificateRequestHandler:
    """Handle certificate-request events (e.g., EST simpleenroll).

    Contract: for a matching, published workflow this will ALWAYS advance a
    brand-new or still-starting/running instance synchronously until the FIRST
    stopping state, then return that state (AwaitingApproval/Approved/Rejected/
    Completed/Failed). Callers will never see "Starting" from this handler.
    """

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
        # -- normalize incoming IDs to ints or None --
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

        # -- load & fingerprint CSR PEM --
        csr_pem = payload.get('csr_pem')
        if not isinstance(csr_pem, str):
            logger.error('certificate_request: missing csr_pem')
            return {'status': 'error', 'msg': 'Missing or invalid csr_pem'}

        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        except Exception as exc:  # noqa: BLE001
            logger.exception('certificate_request: failed to parse CSR PEM')
            return {'status': 'error', 'msg': f'Invalid CSR: {exc!s}'}

        fingerprint = hashlib.sha256(csr.tbs_certrequest_bytes).hexdigest()
        logger.debug('certificate_request: CSR fingerprint=%s', fingerprint)

        # -- scope filter (NULL means "any") --
        definitions = (
            WorkflowDefinition.objects.filter(published=True)
            .filter(
                Q(scopes__ca_id=ca) | Q(scopes__ca_id__isnull=True),
                Q(scopes__domain_id=dom) | Q(scopes__domain_id__isnull=True),
                Q(scopes__device_id=dev) | Q(scopes__device_id__isnull=True),
            )
            .distinct()
        )
        logger.info(
            'certificate_request: matching definitions by scope -> %d candidates',
            definitions.count(),
        )

        # -- try each candidate until one matches the trigger --
        for wf in definitions:
            meta = wf.definition or {}
            nodes = meta.get('nodes', [])
            if not nodes:
                logger.warning('certificate_request: skip %r (no nodes)', wf.name)
                continue

            triggers = meta.get('triggers', [])
            matches = any(
                (t.get('protocol') == protocol and t.get('operation') == operation)
                for t in triggers
            )
            if not matches:
                continue

            logger.info(
                'certificate_request: workflow match name=%r protocol=%s operation=%s',
                wf.name, protocol, operation,
            )

            # Reuse existing instance (any non-finalized state), or create
            inst = (
                WorkflowInstance.objects.filter(
                    definition=wf,
                    payload__fingerprint=fingerprint,
                    finalized=False,
                )
                .order_by('-created_at')
                .first()
            )

            if inst is None:
                # Create new instance at first node
                first_step = nodes[0]['id']
                full_payload = {
                    'protocol': protocol,
                    'operation': operation,
                    'ca_id': ca,
                    'domain_id': dom,
                    'device_id': dev,
                    'fingerprint': fingerprint,
                    **{k: v for k, v in payload.items()},
                }
                with transaction.atomic():
                    inst = WorkflowInstance.objects.create(
                        definition=wf,
                        current_step=first_step,
                        state=WorkflowInstance.STATE_STARTING,
                        payload=full_payload,
                    )
                logger.info(
                    'certificate_request: created instance id=%s workflow=%r step=%s',
                    inst.id, wf.name, first_step,
                )
            else:
                logger.info(
                    'certificate_request: reusing instance id=%s state=%s',
                    inst.id, inst.state,
                )

            # Advance fresh/active instances to first stopping state
            if inst.state in {WorkflowInstance.STATE_STARTING, WorkflowInstance.STATE_RUNNING}:
                logger.debug('certificate_request: advancing instance id=%s', inst.id)
                advance_instance(inst)
                inst.refresh_from_db()
                logger.info(
                    'certificate_request: advanced instance id=%s -> state=%s step=%s',
                    inst.id, inst.state, inst.current_step,
                )

            # Return the (now stable) state for caller branching
            return {'status': inst.state, 'instance_id': str(inst.id)}

        # -- nothing matched --
        logger.info('certificate_request: no matching workflow for protocol=%s op=%s', protocol, operation)
        return {'status': WorkflowInstance.STATE_NO_MATCH}
