"""Workflow models: definitions, scopes, instances, and enrollment requests."""

from __future__ import annotations

import uuid
from typing import Any, cast

from devices.models import DeviceModel
from django.db import models
from django.db.models import JSONField
from pki.models.domain import DomainModel
from pki.models.issuing_ca import IssuingCaModel

# -------------------------------
# Workflow definitions + scoping
# -------------------------------


class State(models.TextChoices):
    """Workflow and enrollment states."""

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

    # Direct match (covers State enum members)
    if key in BADGE_MAP:
        return BADGE_MAP[key]

    # Normalized string match (defensive)
    norm = key.strip().lower()
    for state_key, badge in BADGE_MAP.items():
        if state_key.lower() == norm:
            return badge

    # Fallback: unknown but not None
    return key, 'bg-secondary text-light'


class WorkflowDefinition(models.Model):
    """Blueprint of a workflow: event, steps, transitions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    version = models.PositiveIntegerField(default=1)
    published = models.BooleanField(default=False)
    definition = JSONField()  # {"events":[...], "steps":[...]}
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database configuration for workflow definitions."""

        db_table = 'workflow_definitions'
        ordering = ('-created_at',)

    def __str__(self) -> str:
        """Return human-readable representation with version."""
        return f'{self.name} v{self.version}'


class WorkflowScope(models.Model):
    """Assign a workflow to CAs, domains, or devices (NULL = any)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workflow = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='scopes')
    ca_id = models.IntegerField(null=True, blank=True)
    domain_id = models.IntegerField(null=True, blank=True)
    device_id = models.IntegerField(null=True, blank=True)

    class Meta:
        """Database configuration for Workflow Scope."""

        db_table = 'workflow_scopes'
        unique_together = (('workflow', 'ca_id', 'domain_id', 'device_id'),)

    def __str__(self) -> str:
        """Return human-readable representation."""
        parts: list[str] = []
        if self.ca_id is not None:
            parts.append(f'CA={self.ca_id}')
        if self.domain_id is not None:
            parts.append(f'Domain={self.domain_id}')
        if self.device_id is not None:
            parts.append(f'Device={self.device_id}')
        suffix = ', '.join(parts) if parts else 'any'
        return f'{self.workflow.name} [{suffix}]'


class DeviceRequest(models.Model):
    """Represents a device lifecycle request (creation, deletion, onboarding).

    Attributes:
        id: UUID primary key.
        device: Target device.
        domain: Domain at the time of event (may be null).
        ca: CA for domain (if applicable).
        action: Device action type ("created", "onboarded", "deleted").
        payload: Raw event payload from the handler.
        aggregated_state: Aggregate state over all workflow instances.
        finalized: True if all workflow instances have reached terminal states.
        created_at: Request creation timestamp.
        updated_at: Last update timestamp.
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

    action = models.CharField(max_length=32)  # "created", "onboarded", "deleted"
    payload = models.JSONField(default=dict, blank=True)

    aggregated_state = models.CharField(
        max_length=32,
        choices=State.choices,
        default=State.AWAITING,
    )

    finalized = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database configuration for device workflow parent."""

        ordering = ['-created_at']

    def recompute_and_save(self) -> None:
        """Recompute the aggregate final state from instances."""
        instances = self.instances.all()

        if not instances.exists():
            self.aggregated_state = State.AWAITING
            self.finalized = False
        else:
            states = {inst.state for inst in instances}
            if any(s == State.FAILED for s in states):
                self.aggregated_state = State.FAILED
            elif all(s in {State.FINALIZED, State.ABORTED} for s in states):
                self.aggregated_state = State.FINALIZED
            elif any(s == State.AWAITING for s in states):
                self.aggregated_state = State.AWAITING
            else:
                self.aggregated_state = State.RUNNING

            self.finalized = all(inst.finalized for inst in instances)

        self.save(update_fields=['aggregated_state', 'finalized', 'updated_at'])

    @property
    def badge_class(self) -> str:
        """Return the CSS class for the aggregated state badge."""
        return get_status_badge(self.aggregated_state)[1]
    
    def abort(self) -> None:
        """Abort this request and all non-finalized child workflow instances."""
        if self.finalized:
            return

        self.aggregated_state = State.ABORTED
        self.finalized = True
        self.save(update_fields=["aggregated_state", "finalized", "updated_at"])

        for inst in self.instances.filter(finalized=False):
            inst.finalize(State.ABORTED)


# -------------------------------------
# EnrollmentRequest (EST fan-out parent)
# -------------------------------------


class EnrollmentRequest(models.Model):
    """A single logical certificate enrollment attempt (EST simpleenroll fan-out parent).

    - Aggregates all child WorkflowInstances that must approve/reject this attempt.
    - Identity tuple groups repeated polls for the same CSR until a terminal outcome.
    - We keep request-level states distinct from instance-level strings to avoid confusion.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Identity tuple (NOT unique → allow a new attempt after terminal)
    protocol = models.CharField(max_length=50)
    operation = models.CharField(max_length=50)
    device = models.ForeignKey(DeviceModel, on_delete=models.CASCADE, related_name='device', null=True, blank=True)
    domain = models.ForeignKey(DomainModel, on_delete=models.CASCADE, related_name='domain', null=True, blank=True)
    ca = models.ForeignKey(IssuingCaModel, on_delete=models.CASCADE, related_name='ca', null=True, blank=True)
    fingerprint = models.CharField(max_length=128)  # CSR fingerprint (sha256 hex)
    template = models.CharField(max_length=100, blank=True, default='')

    aggregated_state = models.CharField(max_length=32, choices=State.choices, default=State.AWAITING)
    finalized = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database configuration for enrollment request."""

        db_table = 'enrollment_requests'
        indexes = (
            # Fast lookup by identity tuple when reusing the "open" request
            models.Index(
                fields=['protocol', 'operation', 'ca_id', 'domain_id', 'device_id', 'fingerprint', 'template']
            ),
            models.Index(fields=['aggregated_state']),
            models.Index(fields=['finalized']),
        )

    def __str__(self) -> str:
        """Return human-readable representation."""
        return (
            f'EnrollReq#{self.pk} {self.aggregated_state} {self.protocol}/{self.operation} fp={self.fingerprint[:8]}…'
        )

    @property
    def badge_label(self) -> str:
        """Return the human-readable badge label for the aggregated state."""
        label, _ = get_status_badge(self.aggregated_state)
        return label

    @property
    def badge_class(self) -> str:
        """Return the CSS class for the aggregated state badge."""
        _, css = get_status_badge(self.aggregated_state)
        return css

    # ---- aggregation helpers ----
    def recompute_status(self) -> State:
        """Compute aggregate status from child instances.

        Returns:
            The new aggregated state derived from child instance states.
        """
        children_qs = self.instances.all()
        if not children_qs.exists():
            return State.PASSED

        inst_states = set(children_qs.values_list('state', flat=True))

        if State.REJECTED in inst_states:
            result: State = State.REJECTED
        elif State.FAILED in inst_states:
            result = State.FAILED
        elif State.ABORTED in inst_states:
            result = State.ABORTED
        elif State.AWAITING in inst_states or State.RUNNING in inst_states:
            result = State.AWAITING
        elif inst_states.issubset({State.APPROVED, State.PASSED}):
            result = State.APPROVED
        else:
            result = State.AWAITING

        return result

    def is_valid(self) -> bool:
        """Return True if the enrollment request is in a successful terminal state."""
        return self.aggregated_state in {State.APPROVED, State.PASSED}

    def recompute_and_save(self) -> State:
        """Recalculate the aggregated state and persist changes if it changed.

        Returns:
            The (possibly unchanged) aggregated state.
        """
        new_status = self.recompute_status()
        if new_status != self.aggregated_state:
            self.aggregated_state = new_status
            self.save(update_fields=['aggregated_state', 'updated_at'])
        return State(self.aggregated_state)

    def finalize(self, final_status: str | State | None = None) -> None:
        """Finalize this request and all non-finalized child workflow instances.

        Args:
            final_status: Optional final aggregated state to set for the request.
        """
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


# -------------------------------
# Workflow instances (children)
# -------------------------------


class WorkflowInstance(models.Model):
    """An initialized workflows."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    definition = models.ForeignKey(WorkflowDefinition, on_delete=models.CASCADE, related_name='instances')

    # link to parent EnrollmentRequest (EST fan-out)
    enrollment_request = models.ForeignKey(
        EnrollmentRequest,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='instances',
        help_text='Parent request for EST fan-out orchestration.',
    )
    device_request = models.ForeignKey(
        DeviceRequest,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='instances',
    )

    current_step = models.CharField(max_length=100, help_text='The step-ID we are currently at (e.g. "step-1")')
    state = models.CharField(max_length=32, choices=State.choices, default=State.RUNNING)

    payload = JSONField(help_text='Immutable inputs (eg. CSR fingerprint, CA/Domain/Device IDs)')
    step_contexts = JSONField(
        default=dict,
        help_text=('Mutable per-step storage: e.g. for Approval, email-sent flag; for Timer, deadline timestamp; etc.'),
    )
    finalized = models.BooleanField(
        default=False,
        help_text='Once true, this instance will never be re-queued or advanced again.',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database configuration and indexes for workflow instances."""

        db_table = 'workflow_instances'
        indexes = (
            models.Index(fields=['state']),
            models.Index(fields=['finalized']),
        )

    def __str__(self) -> str:
        """Return a short identifier containing definition name, PK, and state."""
        return f'{self.definition.name}#{self.pk} ({self.state})'

    @property
    def badge_label(self) -> str:
        """Return the human-readable badge label for this instance's state."""
        label, _ = get_status_badge(self.state)
        return label

    @property
    def badge_class(self) -> str:
        """Return the CSS class for this instance's state badge."""
        _, css = get_status_badge(self.state)
        return css

    def finalize(self, state: str | State | None = None) -> None:
        """Mark this instance as fully done and optionally set a final state.

        Args:
            state: Optional final state to set before marking as finalized.
        """
        if self.finalized:
            return

        self.finalized = True
        if state is not None:
            self.state = str(state)
            self.save(update_fields=['state', 'finalized', 'updated_at'])
        else:
            self.save(update_fields=['finalized', 'updated_at'])

    def get_steps(self) -> list[dict[str, Any]]:
        """Return the ordered list of steps from the workflow definition.

        Returns:
            List of step dictionaries from the workflow definition JSON.
        """
        return cast('list[dict[str, Any]]', self.definition.definition.get('steps', []))

    def get_current_step_index(self) -> int:
        """Return the index of ``self.current_step`` in the steps list, or raise."""
        for idx, step in enumerate(self.get_steps()):
            if step['id'] == self.current_step:
                return idx
        msg = f'Unknown current_step {self.current_step!r}'
        raise ValueError(msg)

    def get_next_step(self) -> str | None:
        """Return the step-ID of the next step, or None if at the end.

        Returns:
            Step ID string of the next step, or None if there is no next step.
        """
        idx = self.get_current_step_index()
        steps = self.get_steps()
        if idx + 1 < len(steps):
            return str(steps[idx + 1]['id'])
        return None

    def is_last_approval_step(self) -> bool:
        """Return True if the current step is the last Approval step in the workflow."""
        approval_ids = [step['id'] for step in self.get_steps() if step['type'] == 'Approval']
        return bool(approval_ids and self.current_step == approval_ids[-1])
