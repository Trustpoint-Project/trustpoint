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


def get_status_badge(raw: str | State) -> StatusBadge:
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


# -------------------------------------
# EnrollmentRequest (EST fan-out parent)
# -------------------------------------


class EnrollmentRequest(models.Model):
    """A single logical certificate enrollment attempt (EST simpleenroll fan-out parent).

    - Aggregates all child WorkflowInstances that must approve/reject this attempt.
    - Identity tuple groups repeated polls for the same CSR until a terminal outcome.
    - We keep request-level states distinct from instance-level strings to avoid confusion.
    """

    STATE_AWAITING = State.AWAITING
    STATE_APPROVED = State.APPROVED
    STATE_PASSED = State.PASSED
    STATE_REJECTED = State.REJECTED
    STATE_FAILED = State.FAILED
    STATE_FINALIZED = State.FINALIZED
    STATE_ABORTED = State.ABORTED

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
    def recompute_status(self) -> str:
        """Compute aggregate status from child instances."""
        children = list(self.instances.all())
        if not children:
            return State.PASSED

        inst_states = {c.state for c in children}

        if State.REJECTED in inst_states:
            result = State.REJECTED
        elif State.FAILED in inst_states:
            result = State.FAILED
        elif State.ABORTED in inst_states:
            result = State.ABORTED
        elif State.AWAITING in inst_states or State.RUNNING in inst_states:
            result = State.AWAITING
        elif inst_states.issubset({State.APPROVED, State.FINALIZED}):
            result = State.APPROVED
        else:
            result = State.AWAITING

        return result

    def is_valid(self) -> bool:
        """Return True if the enrollment request is in a successful terminal state."""
        return self.aggregated_state in {State.APPROVED, State.PASSED}

    def recompute_and_save(self) -> str:
        """Recalculate the aggregated state and persist changes if it changed."""
        new_status = self.recompute_status()
        if new_status != self.aggregated_state:
            self.aggregated_state = new_status
            self.save(update_fields=['aggregated_state', 'updated_at'])
        return self.aggregated_state

    def finalize(self, final_status: str | None = None) -> None:
        """Finalize all non-finalized children."""
        self.finalized = True
        if not final_status:
            self.save(update_fields=['finalized'])
        else:
            self.aggregated_state = final_status
            self.save(update_fields=['aggregated_state', 'finalized'])

        for inst in self.instances.filter(finalized=False):
            inst.finalize()
            inst.save(update_fields=['finalized'])

    def abort(self) -> None:
        """Abort this request and all non-finalized child workflow instances."""
        if self.finalized:
            return

        self.aggregated_state = State.ABORTED
        self.finalized = True
        self.save(update_fields=['aggregated_state', 'finalized', 'updated_at'])

        for inst in self.instances.filter(finalized=False):
            # Mark instance as aborted and finalized
            inst.finalize(State.ABORTED)


# -------------------------------
# Workflow instances (children)
# -------------------------------


class WorkflowInstance(models.Model):
    """An initialized workflows."""

    STATE_RUNNING = State.RUNNING
    STATE_AWAITING = State.AWAITING
    STATE_APPROVED = State.APPROVED
    STATE_PASSED = State.PASSED
    STATE_FINALIZED = State.FINALIZED
    STATE_REJECTED = State.REJECTED
    STATE_FAILED = State.FAILED
    STATE_ABORTED = State.ABORTED

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
        """Return the ordered list of steps from the workflow definition."""
        return cast('list[dict[str, Any]]', self.definition.definition.get('steps', []))

    def get_current_step_index(self) -> int:
        """Return the index of ``self.current_step`` in the steps list, or raise."""
        for idx, step in enumerate(self.get_steps()):
            if step['id'] == self.current_step:
                return idx
        msg = f'Unknown current_step {self.current_step!r}'
        raise ValueError(msg)

    def get_next_step(self) -> str | None:
        """Return the step-ID of the next step, or None if at the end."""
        idx = self.get_current_step_index()
        steps = self.get_steps()
        if idx + 1 < len(steps):
            return cast('str', steps[idx + 1]['id'])
        return None

    def is_last_approval_step(self) -> bool:
        """Return True if the current step is the last Approval step in the workflow."""
        approval_ids = [step['id'] for step in self.get_steps() if step['type'] == 'Approval']
        return bool(approval_ids and self.current_step == approval_ids[-1])
