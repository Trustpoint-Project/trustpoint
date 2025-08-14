# workflows/services/evaluator.py
from __future__ import annotations

from typing import Any

from workflows.models import (
    AuditLog,
    WorkflowDefinition,
    WorkflowInstance,
)


class WorkflowEvaluator:
    """Encapsulates logic to find matching workflow definitions and deduplicate/create instances."""

    def find_matching_definitions(
        self,
        *,
        protocol: str,
        operation: str,
        ca_id: Any,
        domain_id: Any,
        device_id: Any,
    ) -> list[WorkflowDefinition]:
        """Return published workflow definitions whose triggers and scopes match this event."""
        # First filter by scope (allows None as wildcard)
        candidate_defs = (
            WorkflowDefinition.objects
            .filter(published=True)
            .filter(
                scopes__ca_id__in=[None, ca_id],
                scopes__domain_id__in=[None, domain_id],
                scopes__device_id__in=[None, device_id],
            )
            .distinct()
        )

        matched: list[WorkflowDefinition] = []
        for definition in candidate_defs:
            triggers = definition.definition.get('triggers', [])
            if any(
                t.get('protocol') == protocol and t.get('operation') == operation
                for t in triggers
            ):
                matched.append(definition)
        return matched

    def get_or_create_instance(
        self,
        *,
        definition: WorkflowDefinition,
        fingerprint: str,
        full_payload: dict[str, Any],
        start_node: str,
    ) -> WorkflowInstance:
        """Given a matching definition and fingerprint, deduplicate an existing non-rejected
        instance or create a new one, logging the creation.
        """
        existing = (
            WorkflowInstance.objects
            .filter(definition=definition, payload__fingerprint=fingerprint)
            .exclude(state=WorkflowInstance.STATE_REJECTED)
            .first()
        )
        if existing:
            return existing

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
        return inst
