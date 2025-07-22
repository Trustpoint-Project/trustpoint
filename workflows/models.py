from __future__ import annotations

import datetime
import uuid
from typing import Any

from django.db.models import JSONField
from django.db import models


class WorkflowDefinition(models.Model):
    """Stores the blueprint of a workflow: triggers, nodes, transitions, versioning."""

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(max_length=100)
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
    ca_id = models.UUIDField(null=True, blank=True)
    domain_id = models.UUIDField(null=True, blank=True)
    device_id = models.UUIDField(null=True, blank=True)

    class Meta:
        db_table = 'workflow_scopes'
        unique_together = [('workflow', 'ca_id', 'domain_id', 'device_id')]


class WorkflowInstance(models.Model):
    """Tracks an active workflow instance: pointer into the graph plus its state."""

    STATE_STARTED = 'Started'
    STATE_AWAITING = 'AwaitingApproval'
    STATE_COMPLETED = 'Completed'
    STATE_REJECTED = 'Rejected'

    STATE_CHOICES = [
        (STATE_STARTED, 'Started'),
        (STATE_AWAITING, 'AwaitingApproval'),
        (STATE_COMPLETED, 'Completed'),
        (STATE_REJECTED, 'Rejected'),
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
    state = models.CharField(max_length=32, choices=STATE_CHOICES)
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
