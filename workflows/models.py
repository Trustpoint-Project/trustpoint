from __future__ import annotations

import uuid

from django.db import models
from django.db.models import JSONField


class WorkflowDefinition(models.Model):
    """Stores the blueprint of a workflow: triggers, nodes, transitions, versioning."""

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(max_length=100, unique=True)
    version = models.PositiveIntegerField(default=1)
    published = models.BooleanField(default=False)
    definition = JSONField()  # {triggers:[...], nodes:[...], transitions:[...] }
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'workflow_definitions'
        ordering = ['-created_at']


class WorkflowScope(models.Model):
    """Assigns workflows to CAs, domains, or devices."""
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    workflow = models.ForeignKey(
        WorkflowDefinition,
        on_delete=models.CASCADE,
        related_name='scopes',
    )
    ca_id = models.IntegerField(null=True, blank=True)
    domain_id = models.IntegerField(null=True, blank=True)
    device_id = models.IntegerField(null=True, blank=True)

    class Meta:
        db_table = 'workflow_scopes'
        unique_together = [('workflow', 'ca_id', 'domain_id', 'device_id')]

class WorkflowInstance(models.Model):
    """Tracks an active workflow instance: pointer into the graph plus its state."""

    STATE_PENDING  = 'pending'
    STATE_ERROR    = 'error'
    STATE_COMPLETE = 'complete'

    STATE_CHOICES = [
        (STATE_PENDING,  'Pending'),
        (STATE_ERROR,    'Error'),
        (STATE_COMPLETE, 'Complete'),
    ]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    definition = models.ForeignKey(
        WorkflowDefinition,
        on_delete=models.PROTECT,
        related_name='instances',
    )
    current_node = models.CharField(max_length=100)
    state = models.CharField(
        max_length=20,
        choices=STATE_CHOICES,
        default=STATE_PENDING,
        help_text='Overall instance status: pending, error, or complete',
    )
    # maps node_id (str) → state (str), e.g. {"step-1":"waiting","step-2":"not_started_yet"}
    step_states = models.JSONField(default=dict)
    payload = JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'workflow_instances'
        indexes = [
            models.Index(fields=['state']),
        ]


class AuditLog(models.Model):
    """Immutable log of every action on a workflow instance."""

    id = models.BigAutoField(primary_key=True)
    instance = models.ForeignKey(
        WorkflowInstance,
        on_delete=models.CASCADE,
        related_name='audit_entries',
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=100, null=True, blank=True)
    action = models.CharField(max_length=100)
    details = JSONField(null=True, blank=True)

    class Meta:
        db_table = 'workflow_audit_log'
        ordering = ['timestamp']
