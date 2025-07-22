from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from django.db import transaction

from workflows.models import (
    AuditLog,
    WorkflowDefinition,
    WorkflowInstance,
)


def handle_certificate_request(
    protocol: str,
    operation: str,
    ca_id: uuid.UUID,
    domain_id: Optional[uuid.UUID],
    device_id: Optional[uuid.UUID],
    payload: Dict[str, Any],
) -> None:
    """Observer callback: start any matching workflows for this certificate request."""
    definitions = WorkflowDefinition.objects.filter(published=True)

    for definition in definitions:
        triggers = definition.definition.get('triggers', [])
        if not any(
            t.get('protocol') == protocol and t.get('operation') == operation
            for t in triggers
        ):
            continue

        for scope in definition.scopes.all():
            matches_device = scope.device_id and scope.device_id == device_id
            matches_domain = scope.domain_id and scope.domain_id == domain_id
            matches_ca = scope.ca_id and scope.ca_id == ca_id
            if not (matches_device or matches_domain or matches_ca):
                continue

            # Create and advance a new instance
            start_node = definition.definition['nodes'][0]['id']
            with transaction.atomic():
                instance = WorkflowInstance.objects.create(
                    definition=definition,
                    current_node=start_node,
                    state=WorkflowInstance.STATE_STARTED,
                    payload=payload,
                )
                AuditLog.objects.create(
                    instance=instance,
                    action='Started',
                    details=payload,
                )
            advance_instance(instance)


def advance_instance(
    instance: WorkflowInstance,
    signal: Optional[str] = None,
) -> None:
    """Move the instance to its next node/state based on the executor’s output."""
    from workflows.services.executors import NodeExecutorFactory

    definition = instance.definition.definition
    node_meta = next(
        n for n in definition['nodes']
        if n['id'] == instance.current_node
    )
    executor = NodeExecutorFactory.create(node_meta['type'])
    next_node, next_state = executor.execute(instance, signal)

    instance.current_node = next_node or instance.current_node
    instance.state = next_state
    instance.save()
