"""Workflow models: definitions, scopes, and instances."""

import uuid
from typing import Any, cast

from django.db import models
from django.db.models import JSONField


class WorkflowDefinition(models.Model):
    """Blueprint of a workflow: triggers, nodes, transitions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    version = models.PositiveIntegerField(default=1)
    published = models.BooleanField(default=False)
    definition = JSONField()  # {"triggers":[...], "nodes":[...], "transitions":[...]}
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata for WorkflowDefinition."""

        db_table = 'workflow_definitions'
        ordering = ('-created_at',)

    def __str__(self) -> str:  # DJ008
        """Return a string representation of the workflow definition."""
        return f'{self.name} v{self.version}'


class WorkflowScope(models.Model):
    """Assign a workflow to CAs, domains, or devices."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workflow = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='scopes')
    ca_id = models.IntegerField(null=True, blank=True)
    domain_id = models.IntegerField(null=True, blank=True)
    device_id = models.IntegerField(null=True, blank=True)

    class Meta:
        """Model metadata for WorkflowScope."""

        db_table = 'workflow_scopes'
        unique_together = (('workflow', 'ca_id', 'domain_id', 'device_id'),)

    def __str__(self) -> str:  # DJ008
        """Return a string representation of the workflow scope."""
        parts = []
        if self.ca_id is not None:
            parts.append(f'CA={self.ca_id}')
        if self.domain_id is not None:
            parts.append(f'Domain={self.domain_id}')
        if self.device_id is not None:
            parts.append(f'Device={self.device_id}')
        suffix = ', '.join(parts) if parts else 'any'
        return f'{self.workflow.name} [{suffix}]'


class WorkflowInstance(models.Model):
    """Tracks an active or completed run through a workflow's nodes."""

    # possible states
    STATE_STARTING = 'Starting'
    STATE_RUNNING = 'Running'
    STATE_AWAITING = 'AwaitingApproval'
    STATE_APPROVED = 'Approved'
    STATE_COMPLETED = 'Completed'
    STATE_REJECTED = 'Rejected'
    STATE_FAILED = 'Failed'
    STATE_CHOICES = (
        (STATE_STARTING, 'Starting'),
        (STATE_RUNNING, 'Running'),
        (STATE_AWAITING, 'AwaitingApproval'),
        (STATE_APPROVED, 'Approved'),
        (STATE_COMPLETED, 'Completed'),
        (STATE_FAILED, 'Failed'),
        (STATE_REJECTED, 'Rejected'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    definition = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='instances')
    current_step = models.CharField(max_length=100, help_text='The node-ID we are currently at (e.g. "step-1")')
    state = models.CharField(max_length=32, choices=STATE_CHOICES, default=STATE_STARTING)
    payload = JSONField(help_text='Immutable inputs (eg. CSR fingerprint, CA/Domain/Device IDs)')
    step_contexts = JSONField(
        default=dict,
        help_text=(
            'Mutable per-step storage: e.g. for Approval, email-sent flag; '
            'for Timer, deadline timestamp; etc.'
        ),
    )
    finalized = models.BooleanField(
        default=False, help_text='Once true, this instance will never be re-queued or advanced again.'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata for WorkflowInstance."""

        db_table = 'workflow_instances'
        indexes = (
            models.Index(fields=['state']),
            models.Index(fields=['finalized']),
        )

    def __str__(self) -> str:  # DJ008
        """Return a string representation of the workflow instance."""
        return f'{self.definition.name}#{self.pk} ({self.state})'

    def finalize(self, state: str | None = None) -> None:
        """Mark this instance as fully done. Optionally set a final state."""
        if self.finalized:
            return
        self.finalized = True
        if state:
            self.state = state
            self.save(update_fields=['state', 'finalized'])
        else:
            self.save(update_fields=['finalized'])

    def get_steps(self) -> list[dict[str, Any]]:
        """Return the ordered list of nodes from the workflow definition."""
        return cast('list[dict[str, Any]]', self.definition.definition.get('nodes', []))

    def get_current_step_index(self) -> int:
        """Return the index of ``self.current_step`` in the node list, or raise."""
        for idx, node in enumerate(self.get_steps()):
            if node['id'] == self.current_step:
                return idx
        msg = f'Unknown current_step {self.current_step!r}'
        raise ValueError(msg)

    def get_next_step(self) -> str | None:
        """Return the node-ID of the next step, or None if at the end."""
        idx = self.get_current_step_index()
        steps = self.get_steps()
        if idx + 1 < len(steps):
            return cast('str', steps[idx + 1]['id'])
        return None

    def is_last_approval_step(self) -> bool:
        """Return True if the current step is the last Approval node in the workflow."""
        approval_ids = [node['id'] for node in self.get_steps() if node['type'] == 'Approval']
        return bool(approval_ids and self.current_step == approval_ids[-1])
