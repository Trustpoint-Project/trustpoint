"""Database models used by the Workflow 2 compiler, runtime, and UI."""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import ClassVar

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

    trigger_on = models.CharField(max_length=100, db_index=True, default='')

    yaml_text = models.TextField()
    ir_json = models.JSONField()
    ir_hash = models.CharField(max_length=64)

    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        """Database indexes for definition lookups."""

        indexes = (
            models.Index(fields=['enabled']),
            models.Index(fields=['trigger_on']),
            models.Index(fields=['ir_hash']),
        )

    def __str__(self) -> str:
        """Return a human-readable representation of the definition."""
        return f'{self.name} ({self.id})'


class Workflow2Run(models.Model):
    """A bundle/run representing one trigger emission that may create multiple instances.

    This is what you'll later use for EST gating / UI grouping.
    """

    STATUS_QUEUED = 'queued'
    STATUS_RUNNING = 'running'
    STATUS_AWAITING = 'awaiting'
    STATUS_PAUSED = 'paused'

    STATUS_SUCCEEDED = 'succeeded'
    STATUS_STOPPED = 'stopped'
    STATUS_REJECTED = 'rejected'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'

    STATUS_NO_MATCH = 'no_match'

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        (STATUS_QUEUED, 'Queued'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_AWAITING, 'Awaiting'),
        (STATUS_PAUSED, 'Paused'),
        (STATUS_SUCCEEDED, 'Succeeded'),
        (STATUS_STOPPED, 'Stopped'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_CANCELLED, 'Cancelled'),
        (STATUS_NO_MATCH, 'No match'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    trigger_on = models.CharField(max_length=100, db_index=True)
    event_json = models.JSONField()
    source_json = models.JSONField(default=dict)

    # Optional idempotency key (for EST polling use-cases etc.)
    idempotency_key = models.CharField(max_length=128, blank=True, default='', db_index=True)

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED)
    finalized = models.BooleanField(default=False)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database indexes for run lookups and filtering."""

        indexes = (
            models.Index(fields=['trigger_on', 'created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['finalized']),
            models.Index(fields=['idempotency_key']),
        )
        constraints = (
            models.UniqueConstraint(
                fields=['trigger_on', 'idempotency_key'],
                condition=~models.Q(idempotency_key=''),
                name='wf2_run_on_idem_uniq',
            ),
        )

    def __str__(self) -> str:
        """Return a human-readable representation of the run."""
        return f'Run {self.id} ({self.trigger_on}) {self.status}'


class Workflow2Instance(models.Model):
    """A single execution of a workflow definition.

    Instance status is the semantic/business lifecycle state.
    This is what users care about.
    """

    STATUS_QUEUED = 'queued'
    STATUS_RUNNING = 'running'
    STATUS_AWAITING = 'awaiting'
    STATUS_PAUSED = 'paused'  # requires manual resume after crash/lease expiry

    # Terminal states
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_STOPPED = 'stopped'
    STATUS_REJECTED = 'rejected'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        (STATUS_QUEUED, 'Queued'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_AWAITING, 'Awaiting'),
        (STATUS_PAUSED, 'Paused'),
        (STATUS_SUCCEEDED, 'Succeeded'),
        (STATUS_STOPPED, 'Stopped'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_CANCELLED, 'Cancelled'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    run = models.ForeignKey(
        Workflow2Run,
        on_delete=models.CASCADE,
        related_name='instances',
        null=True,
        blank=True,
    )

    definition = models.ForeignKey(
        Workflow2Definition,
        on_delete=models.PROTECT,
        related_name='instances',
    )

    event_json = models.JSONField()
    vars_json = models.JSONField(default=dict)

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED)

    # current_step points to NEXT step to execute.
    # For approval awaiting, we keep current_step = approval step id.
    current_step = models.CharField(max_length=200, blank=True, default='')
    run_count = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database indexes for instance monitoring queries."""

        indexes = (
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['run', 'status']),
        )

    def __str__(self) -> str:
        """Return a human-readable representation of the instance."""
        return f'Instance {self.id} ({self.status})'


class Workflow2Approval(models.Model):
    """Persist a pending or resolved approval step decision."""

    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_EXPIRED = 'expired'

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_EXPIRED, 'Expired'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    instance = models.ForeignKey(
        Workflow2Instance,
        on_delete=models.CASCADE,
        related_name='approvals',
    )

    step_id = models.CharField(max_length=200)

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)

    expires_at = models.DateTimeField(null=True, blank=True)

    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.CharField(max_length=128, blank=True, default='')
    comment = models.TextField(blank=True, default='')

    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        """Database indexes for approval queue lookups."""

        indexes = (
            models.Index(fields=['status', 'expires_at']),
            models.Index(fields=['instance', 'step_id']),
        )

    def __str__(self) -> str:
        """Return a human-readable representation of the approval."""
        return f'Approval {self.id} ({self.status})'


class Workflow2StepRun(models.Model):
    """Immutable execution record."""

    id = models.BigAutoField(primary_key=True)

    instance = models.ForeignKey(
        Workflow2Instance,
        on_delete=models.CASCADE,
        related_name='runs',
    )

    run_index = models.PositiveIntegerField()

    step_id = models.CharField(max_length=200)
    step_type = models.CharField(max_length=50)

    status = models.CharField(max_length=16)
    outcome = models.CharField(max_length=100, blank=True, default='')
    next_step = models.CharField(max_length=200, blank=True, default='')
    error = models.TextField(blank=True, default='')

    vars_delta = models.JSONField(null=True, blank=True)
    output = models.JSONField(null=True, blank=True)

    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        """Database indexes for step-run history queries."""

        indexes = (
            models.Index(fields=['instance', 'run_index']),
            models.Index(fields=['step_id']),
        )

    def __str__(self) -> str:
        """Return a human-readable representation of the step run."""
        return f'Run {self.run_index} ({self.step_id})'


class Workflow2Job(models.Model):
    """DB-backed async queue entry.

    Job status is mechanical (scheduler/worker lifecycle), not the same as instance status.
    """

    KIND_RUN = 'run'
    KIND_RESUME = 'resume'

    KIND_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        (KIND_RUN, 'Run'),
        (KIND_RESUME, 'Resume'),
    )

    STATUS_QUEUED = 'queued'
    STATUS_RUNNING = 'running'
    STATUS_DONE = 'done'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        (STATUS_QUEUED, 'Queued'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_DONE, 'Done'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_CANCELLED, 'Cancelled'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    instance = models.ForeignKey(
        Workflow2Instance,
        on_delete=models.CASCADE,
        related_name='jobs',
    )

    kind = models.CharField(max_length=16, choices=KIND_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED)

    run_after = models.DateTimeField(default=timezone.now)

    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True, default='')

    locked_until = models.DateTimeField(null=True, blank=True)
    locked_by = models.CharField(max_length=128, blank=True, default='')

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database indexes for queue polling and worker bookkeeping."""

        indexes = (
            models.Index(fields=['status', 'run_after']),
            models.Index(fields=['locked_until']),
            models.Index(fields=['instance', 'status']),
        )

    def __str__(self) -> str:
        """Return a human-readable representation of the job."""
        return f'Job {self.id} ({self.kind}, {self.status})'

    def lease_expired(self) -> bool:
        """Return whether the job lease has expired or is absent."""
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
        self.locked_by = ''


class Workflow2WorkerHeartbeat(models.Model):
    """Track the last-seen timestamp for a workflow worker process."""

    worker_id = models.CharField(max_length=128, unique=True)
    last_seen = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        """Return a human-readable representation of the worker heartbeat."""
        return f'Worker {self.worker_id}'

    @classmethod
    def beat(cls, worker_id: str) -> None:
        """Record a heartbeat for the given worker identifier."""
        cls.objects.update_or_create(
            worker_id=worker_id,
            defaults={'last_seen': timezone.now()},
        )


class Workflow2DefinitionUiState(models.Model):
    """Editor-only UI layout state.

    Keyed by (definition, ir_hash) so layout is resilient to workflow changes.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    definition = models.ForeignKey(
        Workflow2Definition,
        on_delete=models.CASCADE,
        related_name='ui_states',
    )

    ir_hash = models.CharField(max_length=64, db_index=True)
    version = models.PositiveIntegerField(default=1)
    state_json = models.JSONField(default=dict)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database constraints for editor UI state snapshots."""

        unique_together = (('definition', 'ir_hash'),)
        indexes = (
            models.Index(fields=['definition', 'ir_hash']),
            models.Index(fields=['ir_hash']),
        )

    def __str__(self) -> str:
        """Return a human-readable representation of the UI state."""
        return f'UIState {self.definition} {self.ir_hash[:8]}'
