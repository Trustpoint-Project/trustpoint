"""Workflow models: definitions, scoping, runtime instances, and request parents."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar, cast

from django.db import models

from devices.models import DeviceModel
from pki.models.domain import DomainModel
from pki.models.issuing_ca import IssuingCaModel

# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------


class State(models.TextChoices):
    """Workflow execution and aggregate request states.

    Notes:
        This enum currently mixes:
        - control-flow outcomes (PASSED)
        - blocking outcomes (AWAITING)
        - business outcomes (APPROVED/REJECTED)
        - terminal lifecycle outcomes (FAILED/ABORTED/FINALIZED)

        The engine contract (services/engine.py) defines which statuses advance a step.
    """

    RUNNING = 'Running', 'Running'
    AWAITING = 'AwaitingApproval', 'AwaitingApproval'
    APPROVED = 'Approved', 'Approved'
    PASSED = 'Passed', 'Passed'
    FINALIZED = 'Finalized', 'Finalized'
    REJECTED = 'Rejected', 'Rejected'
    FAILED = 'Failed', 'Failed'
    ABORTED = 'Aborted', 'Aborted'


StatusBadge = tuple[str, str]
"""Tuple of (label, bootstrap_badge_class)."""


BADGE_MAP: dict[str, StatusBadge] = {
    State.RUNNING: ('Running', 'bg-primary'),
    State.AWAITING: ('Awaiting approval', 'bg-warning text-dark'),
    State.APPROVED: ('Approved', 'bg-success'),
    State.REJECTED: ('Rejected', 'bg-danger'),
    State.FAILED: ('Failed', 'bg-danger'),
    State.ABORTED: ('Aborted', 'bg-dark'),
    State.PASSED: ('Passed', 'bg-success'),
    State.FINALIZED: ('Finalized', 'bg-secondary'),
}


def get_status_badge(raw: str | State | None) -> StatusBadge:
    """Return a badge (label, CSS class) for a workflow/enrollment state."""
    if raw is None:
        return 'Unknown', 'bg-light text-muted'

    key = str(raw)
    badge = BADGE_MAP.get(key)
    if badge:
        return badge

    norm = key.strip().lower()
    for state_key, b in BADGE_MAP.items():
        if str(state_key).lower() == norm:
            return b

    return key, 'bg-secondary text-light'


# ---------------------------------------------------------------------------
# Workflow definitions + scoping
# ---------------------------------------------------------------------------


class WorkflowDefinition(models.Model):
    """Blueprint of a workflow: triggers/events, steps, and parameters.

    The 'definition' JSON is treated as design-time data. Runtime state belongs in WorkflowInstance.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    version = models.PositiveIntegerField(default=1)
    published = models.BooleanField(default=False)

    # Expected schema: {"events":[...], "steps":[...]} (current revision)
    definition = models.JSONField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata for workflow definitions."""
        db_table = 'workflow_definitions'
        ordering = ('-created_at',)

    def __str__(self) -> str:
        """Return a human-readable identifier for the workflow definition."""
        return f'{self.name} v{self.version}'


class WorkflowScope(models.Model):
    """Assign a workflow definition to a scope.

    NULL means "any".
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workflow = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='scopes')

    # These were previously IntegerField IDs (ca_id/domain_id/device_id). We use ForeignKey for clarity.
    # db_column preserves the existing column name.
    ca = models.ForeignKey(
        IssuingCaModel,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='workflow_scopes',
        db_column='ca_id',
    )
    domain = models.ForeignKey(
        DomainModel,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='workflow_scopes',
        db_column='domain_id',
    )
    device = models.ForeignKey(
        DeviceModel,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='workflow_scopes',
        db_column='device_id',
    )

    class Meta:
        """Model metadata for workflow scopes."""
        db_table = 'workflow_scopes'
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['workflow', 'ca', 'domain', 'device'],
                name='uq_workflow_scope_workflow_ca_domain_device',
            )
        ]

    def __str__(self) -> str:
        """Return a readable scope description for this workflow assignment."""
        parts: list[str] = []
        if self.ca_id is not None:
            parts.append(f'CA={self.ca_id}')
        if self.domain_id is not None:
            parts.append(f'Domain={self.domain_id}')
        if self.device_id is not None:
            parts.append(f'Device={self.device_id}')
        suffix = ', '.join(parts) if parts else 'any'
        return f'{self.workflow.name} [{suffix}]'


# ---------------------------------------------------------------------------
# Parent request models
# ---------------------------------------------------------------------------


class DeviceRequest(models.Model):
    """Represents a device lifecycle request (creation, onboarding, deletion).

    This is a "fan-out parent": multiple WorkflowInstances can exist per request.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    device = models.ForeignKey(
        DeviceModel,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='device_requests',
    )
    domain = models.ForeignKey(
        DomainModel,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='device_requests',
    )
    ca = models.ForeignKey(
        IssuingCaModel,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='device_requests',
    )

    action = models.CharField(max_length=32)
    payload = models.JSONField(default=dict, blank=True)

    aggregated_state = models.CharField(max_length=32, choices=State.choices, default=State.RUNNING)
    finalized = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata for device requests."""
        ordering = ('-created_at',)

    def __str__(self) -> str:
        """Return a compact string representation for logging and admin UI."""
        device_id = self.device_id if self.device_id is not None else 'None'
        return f'DeviceReq#{self.pk} {self.aggregated_state} action={self.action} device={device_id}'

    def recompute_and_save(self) -> None:
        """Recompute the aggregated state from child instances."""
        instances = self.instances.all()

        if not instances.exists():
            self.aggregated_state = State.FINALIZED
            self.finalized = True
        else:
            states = {str(inst.state) for inst in instances}
            if State.FAILED in states:
                self.aggregated_state = State.FAILED
            elif all(s in {State.FINALIZED, State.ABORTED, State.PASSED} for s in states):
                self.aggregated_state = State.FINALIZED
                self.finalized = True
                for inst in instances:
                    inst.finalize()
            elif State.AWAITING in states:
                self.aggregated_state = State.AWAITING
            else:
                self.aggregated_state = State.RUNNING

        self.save(update_fields=['aggregated_state', 'finalized', 'updated_at'])

    @property
    def badge_class(self) -> str:
        """Return the Bootstrap badge CSS class for the aggregated state."""
        return get_status_badge(self.aggregated_state)[1]

    def finalize(self, final_status: str | State | None = None) -> None:
        """Finalize this request and all non-finalized child workflow instances."""
        self.finalized = True
        if final_status is None:
            self.save(update_fields=['finalized', 'updated_at'])
        else:
            self.aggregated_state = str(final_status)
            self.save(update_fields=['aggregated_state', 'finalized', 'updated_at'])

        for inst in self.instances.filter(finalized=False):
            inst.finalize()

    def abort(self) -> None:
        """Abort this request and all non-finalized child workflow instances."""
        if self.finalized:
            return

        self.aggregated_state = State.ABORTED
        self.finalized = True
        self.save(update_fields=['aggregated_state', 'finalized', 'updated_at'])

        for inst in self.instances.filter(finalized=False):
            inst.finalize(State.ABORTED)


class EnrollmentRequest(models.Model):
    """A single logical certificate enrollment attempt (fan-out parent).

    Multiple WorkflowInstances can contribute approvals/decisions to this request.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Identity tuple (NOT unique => allow new attempts after terminal outcome)
    protocol = models.CharField(max_length=50)
    operation = models.CharField(max_length=50)

    device = models.ForeignKey(
        DeviceModel,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='enrollment_requests',
    )
    domain = models.ForeignKey(
        DomainModel,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='enrollment_requests',
    )
    ca = models.ForeignKey(
        IssuingCaModel,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='enrollment_requests',
    )

    fingerprint = models.CharField(max_length=128)  # CSR fingerprint (sha256 hex)
    template = models.CharField(max_length=100, blank=True, default='')

    aggregated_state = models.CharField(max_length=32, choices=State.choices, default=State.AWAITING)
    finalized = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata for enrollment requests."""
        db_table = 'enrollment_requests'
        indexes = (
            models.Index(
                fields=['protocol', 'operation', 'ca_id', 'domain_id', 'device_id', 'fingerprint', 'template']
            ),
            models.Index(fields=['aggregated_state']),
            models.Index(fields=['finalized']),
        )

    def __str__(self) -> str:
        """Return a compact string representation for logging and admin UI."""
        return (
            f'EnrollReq#{self.pk} {self.aggregated_state} '
            f'{self.protocol}/{self.operation} fp={self.fingerprint[:8]}…'
        )

    @property
    def badge_label(self) -> str:
        """Return the human-readable badge label for the aggregated state."""
        label, _ = get_status_badge(self.aggregated_state)
        return label

    @property
    def badge_class(self) -> str:
        """Return the Bootstrap badge CSS class for the aggregated state."""
        _, css = get_status_badge(self.aggregated_state)
        return css

    def recompute_status(self) -> State:
        """Compute aggregate status from child instances."""
        children_qs = self.instances.all()
        if not children_qs.exists():
            return State.PASSED

        inst_states = set(children_qs.values_list('state', flat=True))

        status = State.AWAITING
        if State.REJECTED in inst_states:
            status = State.REJECTED
        elif State.FAILED in inst_states:
            status = State.FAILED
        elif State.ABORTED in inst_states:
            status = State.ABORTED
        elif State.AWAITING in inst_states or State.RUNNING in inst_states:
            status = State.AWAITING
        elif inst_states.issubset({State.APPROVED, State.PASSED}):
            status = State.APPROVED

        return status


    def is_valid(self) -> bool:
        """Return True if the request is in a state considered valid/successful."""
        return self.aggregated_state in {State.APPROVED, State.PASSED}

    def recompute_and_save(self) -> State:
        """Recompute aggregated_state and persist it if it changed."""
        new_status = self.recompute_status()
        if str(new_status) != str(self.aggregated_state):
            self.aggregated_state = str(new_status)
            self.save(update_fields=['aggregated_state', 'updated_at'])
        return State(self.aggregated_state)

    def finalize(self, final_status: str | State | None = None) -> None:
        """Finalize this request and all non-finalized child workflow instances."""
        self.finalized = True
        if final_status is None:
            self.save(update_fields=['finalized', 'updated_at'])
        else:
            self.aggregated_state = str(final_status)
            self.save(update_fields=['aggregated_state', 'finalized', 'updated_at'])

        for inst in self.instances.filter(finalized=False):
            inst.finalize()

    def abort(self) -> None:
        """Abort this request and all non-finalized child workflow instances."""
        if self.finalized:
            return

        self.aggregated_state = State.ABORTED
        self.finalized = True
        self.save(update_fields=['aggregated_state', 'finalized', 'updated_at'])

        for inst in self.instances.filter(finalized=False):
            inst.finalize(State.ABORTED)


# ---------------------------------------------------------------------------
# Runtime workflow instances (children)
# ---------------------------------------------------------------------------


class WorkflowInstance(models.Model):
    """A runtime workflow execution of a WorkflowDefinition."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    definition = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='instances')

    enrollment_request = models.ForeignKey(
        EnrollmentRequest,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='instances',
        help_text='Parent request for enrollment fan-out orchestration.',
    )
    device_request = models.ForeignKey(
        DeviceRequest,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='instances',
    )

    current_step = models.CharField(max_length=100, help_text='Current step id (e.g. "step-1").')
    state = models.CharField(max_length=32, choices=State.choices, default=State.RUNNING)

    # Design intent: immutable input snapshot for this instance.
    payload = models.JSONField(help_text='Immutable instance inputs (ids, fingerprint, CSR, etc.).')

    # Engine-managed runtime storage:
    # - step_contexts[<step_id>] = compacted per-step context dict
    # - step_contexts['$vars']   = global vars dict
    step_contexts = models.JSONField(
        default=dict,
        help_text="Mutable runtime storage (per-step contexts + reserved engine buckets like '$vars').",
    )

    finalized = models.BooleanField(
        default=False,
        help_text='Once true, this instance will never be advanced again.',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Model metadata for workflow instances."""
        db_table = 'workflow_instances'
        indexes = (
            models.Index(fields=['state']),
            models.Index(fields=['finalized']),
        )

    def __str__(self) -> str:
        """Return a compact string representation for logging and admin UI."""
        return f'{self.definition.name}#{self.pk} ({self.state})'

    @property
    def badge_label(self) -> str:
        """Return the human-readable badge label for the instance state."""
        label, _ = get_status_badge(self.state)
        return label

    @property
    def badge_class(self) -> str:
        """Return the Bootstrap badge CSS class for the instance state."""
        _, css = get_status_badge(self.state)
        return css

    # ---- convenience accessors (do not change storage format) ----

    @property
    def vars(self) -> dict[str, Any]:
        """Return the engine global vars bucket stored under step_contexts['$vars']."""
        sc = self.step_contexts or {}
        if isinstance(sc, dict):
            v = sc.get('$vars')
            if isinstance(v, dict):
                return v
        return {}

    def finalize(self, state: str | State | None = None) -> None:
        """Mark this instance as fully done and optionally set a final state."""
        if self.finalized:
            return

        self.finalized = True
        if state is not None:
            self.state = str(state)
            self.save(update_fields=['state', 'finalized', 'updated_at'])
        else:
            self.save(update_fields=['finalized', 'updated_at'])

    def get_steps(self) -> list[dict[str, Any]]:
        """Return the ordered list of steps from the workflow definition JSON."""
        return cast('list[dict[str, Any]]', self.definition.definition.get('steps', []))

    def get_current_step_index(self) -> int:
        """Return the index of current_step in the steps list, or raise."""
        for idx, step in enumerate(self.get_steps()):
            if step['id'] == self.current_step:
                return idx
        msg = f'Unknown current_step {self.current_step!r}'
        raise ValueError(msg)

    def get_next_step(self) -> str | None:
        """Return the step-id of the next step, or None if at the end."""
        idx = self.get_current_step_index()
        steps = self.get_steps()
        if idx + 1 < len(steps):
            return str(steps[idx + 1]['id'])
        return None

    def is_last_approval_step(self) -> bool:
        """Return True if the current step is the last Approval step in the workflow."""
        approval_ids = [step['id'] for step in self.get_steps() if step.get('type') == 'Approval']
        return bool(approval_ids and self.current_step == approval_ids[-1])
