from __future__ import annotations

import uuid
from datetime import timedelta

from django.db import models
from django.utils import timezone


class Workflow2Definition(models.Model):
    """Workflow definition (v2). Stored as YAML + compiled IR.

    Note:
      - trigger_on is denormalized for fast selection at runtime.
      - IR remains the source of truth.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=200)
    enabled = models.BooleanField(default=True)

    trigger_on = models.CharField(max_length=100, db_index=True, default="")

    yaml_text = models.TextField()
    ir_json = models.JSONField()
    ir_hash = models.CharField(max_length=64)

    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=["enabled"]),
            models.Index(fields=["trigger_on"]),
            models.Index(fields=["ir_hash"]),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.id})"


class Workflow2Instance(models.Model):
    """A single execution of a workflow definition.

    Instance status is the semantic/business lifecycle state.
    This is what users care about.
    """

    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_AWAITING = "awaiting"
    STATUS_PAUSED = "paused"        # <-- NEW: requires manual resume after crash

    # Terminal states (explicitly distinct)
    STATUS_SUCCEEDED = "succeeded"
    STATUS_STOPPED = "stopped"
    STATUS_FAILED = "failed"
    STATUS_CANCELLED = "cancelled"

    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_AWAITING, "Awaiting"),
        (STATUS_PAUSED, "Paused"),   # <-- NEW
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_STOPPED, "Stopped"),
        (STATUS_FAILED, "Failed"),
        (STATUS_CANCELLED, "Cancelled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    definition = models.ForeignKey(
        Workflow2Definition,
        on_delete=models.PROTECT,
        related_name="instances",
    )

    event_json = models.JSONField()
    vars_json = models.JSONField(default=dict)

    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_QUEUED,
    )

    current_step = models.CharField(max_length=200, null=True, blank=True)
    run_count = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"Instance {self.id} ({self.status})"


class Workflow2StepRun(models.Model):
    """Immutable execution record."""

    id = models.BigAutoField(primary_key=True)

    instance = models.ForeignKey(
        Workflow2Instance,
        on_delete=models.CASCADE,
        related_name="runs",
    )

    run_index = models.PositiveIntegerField()

    step_id = models.CharField(max_length=200)
    step_type = models.CharField(max_length=50)

    status = models.CharField(max_length=16)
    outcome = models.CharField(max_length=100, null=True, blank=True)
    next_step = models.CharField(max_length=200, null=True, blank=True)

    vars_delta = models.JSONField(null=True, blank=True)
    output = models.JSONField(null=True, blank=True)
    error = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=["instance", "run_index"]),
            models.Index(fields=["step_id"]),
        ]

    def __str__(self) -> str:
        return f"Run {self.run_index} ({self.step_id})"


class Workflow2Job(models.Model):
    """DB-backed async queue entry.

    Job status is mechanical (scheduler/worker lifecycle), not the same as instance status.
    """

    KIND_RUN = "run"
    KIND_RESUME = "resume"

    KIND_CHOICES = [
        (KIND_RUN, "Run"),
        (KIND_RESUME, "Resume"),
    ]

    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_DONE = "done"
    STATUS_FAILED = "failed"
    STATUS_CANCELLED = "cancelled"

    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_DONE, "Done"),
        (STATUS_FAILED, "Failed"),
        (STATUS_CANCELLED, "Cancelled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    instance = models.ForeignKey(
        Workflow2Instance,
        on_delete=models.CASCADE,
        related_name="jobs",
    )

    kind = models.CharField(max_length=16, choices=KIND_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED)

    run_after = models.DateTimeField(default=timezone.now)

    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=6)
    last_error = models.TextField(null=True, blank=True)

    locked_until = models.DateTimeField(null=True, blank=True)
    locked_by = models.CharField(max_length=128, null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["status", "run_after"]),
            models.Index(fields=["locked_until"]),
            models.Index(fields=["instance", "status"]),
        ]

    def lease_expired(self) -> bool:
        if self.locked_until is None:
            return True
        return self.locked_until <= timezone.now()

    def schedule_retry(self, *, error: str) -> None:
        """Exponential backoff: 1m,2m,4m,8m,16m,32m (capped)."""
        self.attempts += 1
        self.last_error = error

        delay_minutes = min(2 ** max(self.attempts - 1, 0), 60)
        self.run_after = timezone.now() + timedelta(minutes=delay_minutes)

        self.status = self.STATUS_QUEUED
        self.locked_until = None
        self.locked_by = None
